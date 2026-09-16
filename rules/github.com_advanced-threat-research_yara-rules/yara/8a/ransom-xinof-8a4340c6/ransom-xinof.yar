rule ransom_xinof 
{
   meta:
      description = "Detect Xinof ransomware"
      author = "Thomas Roccia | McAfee ATR team"
      reference = "https://labs.sentinelone.com/the-fonix-raas-new-low-key-threat-with-unnecessary-complexities/"
      date = "2020-11-20"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom/XINOF"
      actor_type = "Cybercrime"
      actor_group = "FONIX"
      hash = "0C1E6299A2392239DBE7FEAD33EF4146"

   strings:
      $s1 = "XINOF.exe" nocase ascii
      $s2 = "C:\\Users\\Phoenix" nocase ascii
      $s3 = "How To Decrypt Files.hta" nocase ascii
      $s4 = "C:\\ProgramData\\norunanyway" nocase ascii
      $s5 = "C:\\ProgramData\\clast" nocase ascii
      $s6 = "fonix1" nocase ascii
      $s7 = "C:\\Windows\\System32\\shatdown.exe" nocase ascii
      $s8 = "XINOF Ransomw" nocase ascii
      $s9 = "XINOF v4.2" nocase ascii
      $s10 = "XINOF Ransomware Version 3.3" nocase ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      5 of ($s*) or ransom_xinof_chunk
}
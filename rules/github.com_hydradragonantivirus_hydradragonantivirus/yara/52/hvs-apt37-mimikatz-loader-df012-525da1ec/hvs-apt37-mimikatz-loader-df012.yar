import "pe"
rule HvS_APT37_mimikatz_loader_DF012 {
   meta:
      description = "Loader for encrypted Mimikatz variant used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "42e4a9aeff3744bbbc0e82fd5b93eb9b078460d8f40e0b61b27b699882f521be"
   strings:
      $s1 = ".?AVCEncryption@@" fullword ascii
      $s2 = "afrfa"
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 
      (pe.imphash() == "fa0b87c7e07d21001355caf7b5027219") and (all of them)
}
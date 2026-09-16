import "pe"
rule mimikatz_utility_softcell {

   meta:

      description = "Rule to detect Mimikatz utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "hacktool"
      malware_family = "Hacktool:W32/Mimikatz"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "livessp.dll" fullword wide 
      $s2 = "\\system32\\tapi32.dll" fullword wide
      $s3 = " * Process Token : " fullword wide
      $s4 = "lsadump" fullword wide
      $s5 = "-nl - skip lsa dump..." fullword wide
      $s6 = "lsadump::sam" fullword wide
      $s7 = "lsadump::lsa" fullword wide
      $s8 = "* NL$IterCount %u, %u real iter(s)" fullword wide
      $s9 = "* Iter to def (%d)" fullword wide
      $s10 = " * Thread Token  : " fullword wide
      $s11 = " * RootKey  : " fullword wide
      $s12 = "lsadump::cache" fullword wide
      $s13 = "sekurlsa::logonpasswords" fullword wide
      $s14 = "(commandline) # %s" fullword wide
      $s15 = ">>> %s of '%s' module failed : %08x" fullword wide
      $s16 = "UndefinedLogonType" fullword wide
      $s17 = " * Username : %wZ" fullword wide
      $s18 = "logonPasswords" fullword wide
      $s19 = "privilege::debug" fullword wide
      $s20 = "token::elevate" fullword wide

      $op0 = { e8 0b f5 00 00 90 39 35 30 c7 02 00 75 34 48 8b }
      $op1 = { eb 34 48 8b 4d cf 48 8d 45 c7 45 33 c9 48 89 44 }
      $op2 = { 48 3b 0d 34 26 01 00 74 05 e8 a9 31 ff ff 48 8b }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 500KB and
      ( pe.imphash() == "169e02f00c6fb64587297444b6c41ff4" and
      all of them )
}
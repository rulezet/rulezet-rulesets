import "pe"
rule poison_ivy_softcell {

   meta:

      description = "Rule to detect Poison Ivy used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "rat"
      malware_family = "Rat:W32/PoisonIvy"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s3 = "&Enter password for the encrypted file:" fullword wide
      $s4 = "start \"\" \"%CD%\\mcoemcpy.exe\"" fullword ascii
      $s5 = "setup.bat" fullword ascii
      $s6 = "ErroraErrors encountered while performing the operation" fullword wide
      $s7 = "Please download a fresh copy and retry the installation" fullword wide
      $s8 = "antivir.dat" fullword ascii
      $s9 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
      $s10 = "=Total path and file name length must not exceed %d characters" fullword wide
      $s11 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide

      $op0 = { e8 6f 12 00 00 84 c0 74 04 32 c0 eb 34 56 ff 75 }
      $op1 = { 53 68 b0 34 41 00 57 e8 61 44 00 00 57 e8 31 44 }
      $op2 = { 56 ff 75 08 8d b5 f4 ef ff ff e8 17 ff ff ff 8d }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 500KB and
      ( pe.imphash() == "dbb1eb5c3476069287a73206929932fd" and
      all of them)
}
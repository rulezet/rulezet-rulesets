rule Ransom_Ryuk_sept2020 {
   meta:
      description = "Detecting latest Ryuk samples"
      author = "McAfe ATR"
      date = "2020-10-13"
       malware_type = "ransomware"
      malware_family = "Ransom:W32/Ryuk"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "cfdc2cb47ef3d2396307c487fc3c9fe55b3802b2e570bee9aea4ab1e4ed2ec28"
   strings:
      $x1 = "\" /TR \"C:\\Windows\\System32\\cmd.exe /c for /l %x in (1,1,50) do start wordpad.exe /p " fullword ascii
      $x2 = "cmd.exe /c \"bcdedit /set {default} recoveryenabled No & bcdedit /set {default}\"" fullword ascii
      $x3 = "cmd.exe /c \"bootstatuspolicy ignoreallfailures\"" fullword ascii
      $x4 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet\"" fullword ascii
      $x5 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x6 = "cmd.exe /c \"WMIC.exe shadowcopy delete\"" fullword ascii
      $x7 = "/C REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /t REG_SZ /d \"" fullword wide
      $x8 = "W/C REG DELETE \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /f" fullword wide
      $x9 = "\\System32\\cmd.exe" fullword wide
      $s10 = "Ncsrss.exe" fullword wide
      $s11 = "lsaas.exe" fullword wide
      $s12 = "lan.exe" fullword wide
      $s13 = "$WGetCurrentProcess" fullword ascii
      $s14 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s15 = "Ws2_32.dll" fullword ascii
      $s16 = " explorer.exe" fullword wide
      $s17 = "e\\Documents and Settings\\Default User\\" fullword wide
      $s18 = "\\users\\Public\\" fullword ascii
      $s19 = "\\users\\Public\\sys" fullword wide
      $s20 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii

      $seq0 = { 2b c7 50 e8 30 d3 ff ff ff b6 8c }
      $seq1 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
      $seq2 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
   condition:
      ( uint16(0) == 0x5a4d and 
      filesize < 400KB and 
      ( 1 of ($x*) and 5 of them ) and 
      all of ($seq*)) or ( all of them )
}
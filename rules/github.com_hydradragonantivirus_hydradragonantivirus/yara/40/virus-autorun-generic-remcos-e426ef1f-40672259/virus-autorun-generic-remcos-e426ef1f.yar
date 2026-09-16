rule Virus_Autorun_Generic_Remcos_E426EF1F {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Generic.Remcos.E426EF1F.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dfb52b305df88d4150b6bef39e62939710deb74cf2e7ca3cca518da1b6943e9"

  strings:
    $s1  = "[+] before ShellExec" fullword ascii
    $s2  = "[+] ShellExec success" fullword ascii
    $s3  = "Keylogger initialization failure: error " fullword ascii
    $s4  = "[-] CoGetObject FAILURE" fullword ascii
    $s5  = "Offline Keylogger Stopped" fullword ascii
    $s6  = "Online Keylogger Stopped" fullword ascii
    $s7  = "Executing file: " fullword ascii
    $s8  = "[+] CoGetObject SUCCESS" fullword ascii
    $s9  = "[Chrome StoredLogins found, cleared!]" fullword ascii
    $s10 = "[Firefox StoredLogins not found]" fullword ascii
    $s11 = "[Chrome StoredLogins not found]" fullword ascii
    $s12 = "Connection Failed: " fullword ascii
    $s13 = "Connection Error: Unable to create socket" fullword ascii
    $s14 = "ReadFile error" fullword ascii
    $s15 = "Downloading file: " fullword ascii
    $s16 = "Failed to load TLS key" fullword ascii
    $s17 = "Downloaded file: " fullword ascii
    $s18 = "Failed to upload file: " fullword ascii
    $s19 = "Remcos Agent initialized" fullword ascii
    $s20 = "[Chrome Cookies not found]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}
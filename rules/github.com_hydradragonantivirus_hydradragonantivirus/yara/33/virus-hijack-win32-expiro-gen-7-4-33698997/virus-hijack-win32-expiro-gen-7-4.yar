rule Virus_Hijack_Win32_Expiro_Gen_7_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Expiro.Gen.7_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72f26dbd3a9d0819da661624b62f1898ace7974f963f96d11b56b1c99b96c63f"

  strings:
    $s1  = " <action type=\"Label\" target=\"setup/loginheader\" xmbdesc=\"Label(setup/loginheader)\">" fullword ascii
    $s2  = "  <xmbtext>Login Unauthorized - Please try again later.</xmbtext>" fullword ascii
    $s3  = "  <xmbtext>Login Unauthorised - Please try again later</xmbtext>" fullword ascii
    $s4  = "Failed to get handle (%d) - %s" fullword ascii
    $s5  = "  <xmbtext>Login Unauthorized - Please try again later</xmbtext>" fullword ascii
    $s6  = "  <xmbtext>Login Unauthorised - Please try again later.</xmbtext>" fullword ascii
    $s7  = "  <xmbtext>Nicht autorisiertes Login - Bitte versuchen Sie es sp" fullword ascii
    $s8  = "+Login Unauthorized - Please try again later" fullword wide
    $s9  = "wininet.dll version: %s" fullword ascii
    $s10 = "Failed to get proxy authentication (%d - %d)" fullword ascii
    $s11 = "Failed to ping server - no valid internet connection detected." fullword ascii
    $s12 = "Upload Status: %s - %d%%  (%d left)" fullword ascii
    $s13 = "<html><head><META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=utf-8'></head><body bgcolor='#eeeeee'><style>body{font-f" ascii
    $s14 = " <action type=\"Label\" target=\"setup/description\" xmbdesc=\"Label(setup/description)\">" fullword ascii
    $s15 = "Please log in as %s to complete the operation." fullword ascii
    $s16 = "Succesfully downloaded autoproxy script." fullword ascii
    $s17 = "Downloading autoproxy script." fullword ascii
    $s18 = "Proxy 407 detecting, attempting to get authentication info" fullword ascii
    $s19 = "%s has crashed.  A crash dump has been generated: %s" fullword ascii
    $s20 = "HTTP Error %d - %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}
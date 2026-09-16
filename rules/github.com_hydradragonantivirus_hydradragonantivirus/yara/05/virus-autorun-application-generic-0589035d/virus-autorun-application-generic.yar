rule Virus_Autorun_Application_Generic {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Application.Generic.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2dfd5beb3cebf5016a2e42e9cfa90dec80e54c7d84069c2819a1c9d50044313"

  strings:
    $s1 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii
    $s2 = "</security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{4a2f2" ascii
    $s3 = "</security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{4a2f2" ascii
    $s4 = "Yair Rozenblum 151" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}
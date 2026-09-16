rule VirusShareTrojanClick331128_3 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanClick331128_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d8c5b4bdd96f0cd3af20f70aa3f2930d74e81a80f630f0889b492de96280fb7"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "A universal launcher for PortableApps.com applications." fullword wide
    $s3 = "SoftPerfect Network Scanner Portable Launcher" fullword wide
    $s4 = "SoftPerfect Network Scanner Portable" fullword wide
    $s5 = " Install System v2.46.5-ANSI</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windo" ascii
    $s6 = "mpatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e2011457-1546-43c5-" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}
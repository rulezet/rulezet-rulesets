rule VirusShareTrojanPacked19697 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPacked19697.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "852ee75bdcbf6a258a8744b6bc90fd60ccea669f67a0269bef4504c0695afab4"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"GDGSoft.GSplit.SFU\" type=\"win32\"/><description>GSp" ascii
    $s3 = "-Uniting</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\"" ascii
    $s4 = "Error loading Self-Uniting; see version information in order to contact the author." fullword ascii
    $s5 = "GSplit Archive" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}
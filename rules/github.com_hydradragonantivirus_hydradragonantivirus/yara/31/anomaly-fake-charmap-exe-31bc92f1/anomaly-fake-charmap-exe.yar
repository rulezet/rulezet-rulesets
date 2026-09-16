import "pe"
rule Anomaly_Fake_charmap_exe {
  meta:
    author      = "albertzsigovits"
    description = "Anomaly rule for finding fake charmap.exe"

  condition:
    uint16be(0) == 0x4D5A
    and pe.version_info["CompanyName"] contains "Microsoft Corporation"
    and
    (pe.version_info["InternalName"] contains "charmap"
      or pe.version_info["OriginalFilename"] contains "charmap")
    and not
    (pe.version_info["InternalName"] matches /charmap.exe/i
      or pe.version_info["OriginalFilename"] matches /charmap.exe/i)
}
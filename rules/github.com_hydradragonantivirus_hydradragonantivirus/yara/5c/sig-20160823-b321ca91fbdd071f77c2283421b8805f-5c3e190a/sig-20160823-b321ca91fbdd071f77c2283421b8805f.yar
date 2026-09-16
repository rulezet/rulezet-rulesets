rule sig_20160823_b321ca91fbdd071f77c2283421b8805f {
  meta:
    description = "datamaliciousorder - file 20160823_b321ca91fbdd071f77c2283421b8805f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b41aad348f8291ab48ad153eefff4e612279c3498d032ac56e6e090eba70480f"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
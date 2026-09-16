rule sig_20160822_ff5bb04480ceaa4d1470c70c2e252f58 {
  meta:
    description = "datamaliciousorder - file 20160822_ff5bb04480ceaa4d1470c70c2e252f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f9ca615b98caa9d20b439c74e812647468d256a20bbce1c9d6bba7378cb2160"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
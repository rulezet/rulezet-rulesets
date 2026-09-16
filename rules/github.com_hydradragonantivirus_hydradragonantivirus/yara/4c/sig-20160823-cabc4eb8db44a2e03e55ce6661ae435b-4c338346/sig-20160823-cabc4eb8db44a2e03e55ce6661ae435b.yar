rule sig_20160823_cabc4eb8db44a2e03e55ce6661ae435b {
  meta:
    description = "datamaliciousorder - file 20160823_cabc4eb8db44a2e03e55ce6661ae435b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90ef25a723d11167e8ef0abc0bf5fa33a5c780b25c2ecec662d9ba62023b679a"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule sig_20160823_f44a3f46483bbef5fa230d90c25f1d96 {
  meta:
    description = "datamaliciousorder - file 20160823_f44a3f46483bbef5fa230d90c25f1d96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d5f273a11b99f97ec3ccb0463c3e6e04bee41c7b4143a81873c7fbf6b5a0e32"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
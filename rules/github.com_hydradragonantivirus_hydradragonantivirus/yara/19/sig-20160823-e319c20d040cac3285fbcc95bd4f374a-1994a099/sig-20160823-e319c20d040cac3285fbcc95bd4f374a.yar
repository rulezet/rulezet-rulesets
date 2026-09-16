rule sig_20160823_e319c20d040cac3285fbcc95bd4f374a {
  meta:
    description = "datamaliciousorder - file 20160823_e319c20d040cac3285fbcc95bd4f374a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55ce088f7d44c315ed481965ee06e4013c528caa76b1ab9fe4b06fd2967fb2f9"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
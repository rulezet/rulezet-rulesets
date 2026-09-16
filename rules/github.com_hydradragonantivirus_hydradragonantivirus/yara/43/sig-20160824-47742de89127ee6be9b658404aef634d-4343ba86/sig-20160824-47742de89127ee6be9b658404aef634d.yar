rule sig_20160824_47742de89127ee6be9b658404aef634d {
  meta:
    description = "datamaliciousorder - file 20160824_47742de89127ee6be9b658404aef634d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76da4acb80e5a36375da5314893cefe6f87fc9db37f1a29c5f2d30293508360e"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}
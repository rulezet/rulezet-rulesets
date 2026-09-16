rule sig_20160826_621a737f52b04a91b2b775746bafe49b {
  meta:
    description = "datamaliciousorder - file 20160826_621a737f52b04a91b2b775746bafe49b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90e72bae2b0ff62bdde8e513a8625e88c6866753cc354a8bd6e52f86121b00b6"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}
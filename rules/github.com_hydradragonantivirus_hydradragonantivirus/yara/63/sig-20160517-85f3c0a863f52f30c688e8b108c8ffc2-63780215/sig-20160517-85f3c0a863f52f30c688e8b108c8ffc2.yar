rule sig_20160517_85f3c0a863f52f30c688e8b108c8ffc2 {
  meta:
    description = "datamaliciousorder - file 20160517_85f3c0a863f52f30c688e8b108c8ffc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5d41cb010fb390e2a84527d822ad2dd8ba7f081f36d5f4f5fb7f08931516edc"

  strings:
    $s1 = "var gwqzw='vi31agaemrmrrkcz1a litpuxulmxgmfc3cvdh2xcbplms14jmbfjcqlvodkfjr1zohrsvkznfq1oxqpxkzx=hi3xw\\'fhrxptzghdfcao2v3nslt2ai" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
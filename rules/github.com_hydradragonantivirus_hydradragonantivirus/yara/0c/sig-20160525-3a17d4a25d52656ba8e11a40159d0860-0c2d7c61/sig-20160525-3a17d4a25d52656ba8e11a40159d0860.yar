rule sig_20160525_3a17d4a25d52656ba8e11a40159d0860 {
  meta:
    description = "datamaliciousorder - file 20160525_3a17d4a25d52656ba8e11a40159d0860.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28e674c4322c42e979fcc025146f74872a96bffe7ba0ffcb3e3dca6daff2cd23"

  strings:
    $s1 = "darg rav\\n;\"f2x\\\\m\" = modnarg rav\\n;\"237x\\\\\" = deerdg rav\\n;)3(]\"tAra\"+\"86x\\\\\"+\"c\"[ecapsetihwxelfg = sdnetg r" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}
rule sig_20170124_ef5a52102363101235082912e277d31d {
  meta:
    description = "datamaliciousorder - file 20170124_ef5a52102363101235082912e277d31d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48622aa96a21f66b22604036dc1b642a42b295bc2cd8271297393490b5eda6dc"

  strings:
    $s1 = "//if ([\"enowedp\", \"wruresm\", \"apangasq\", \"tsih\", \"yqog\", \"qyfy\", \"cirm\", \"hynjak\", \"ojkyhda\", \"yge\", \"wlylo" ascii
    $s2 = ", \"ijume\", \"yhba\", new Function([\"wupnef\", \"xcubosp\", \"mrihb\", \"cmirqu\", \"elalp\", \"ecysk\", \"isjavo\", \"itufuq" ascii
    $s3 = "nqutryhde2 = this[[\"bqomh\", \"bywiqa\", \"vjiqtyzu\", \"izva\", \"wotalde\", \"pagu\", \"umvytuq\", \"oped\", \"iwoxqu\", \"me" ascii
    $s4 = "nqutryhde2 = this[[\"bqomh\", \"bywiqa\", \"vjiqtyzu\", \"izva\", \"wotalde\", \"pagu\", \"umvytuq\", \"oped\", \"iwoxqu\", \"me" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
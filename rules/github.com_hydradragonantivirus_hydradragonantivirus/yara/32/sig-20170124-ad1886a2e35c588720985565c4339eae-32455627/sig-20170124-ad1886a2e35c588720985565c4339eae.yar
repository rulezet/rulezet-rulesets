rule sig_20170124_ad1886a2e35c588720985565c4339eae {
  meta:
    description = "datamaliciousorder - file 20170124_ad1886a2e35c588720985565c4339eae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35b293bc6053170d8e4c8edbdde43916f6144bf790f702292ed19227ca2ac7fc"

  strings:
    $s1 = "if ([\"vim\", new Function([\"olehekj\", \"tfykypm\", \"hevalka\", \"xigxos\", \"axylquwb\", \"sawuhu\", \"yszezmu\", \"ozivin\"" ascii
    $s2 = "szuwkitq3 = this[[\"izilhy\", \"rvote\", \"elotbax\", \"ehtibja\", \"upciwvag\", \"qwepnuv\", \"qcodlenq\", \"imog\", \"vekbyq\"" ascii
    $s3 = "vny\", \"duvenu\", \"iwvalt\", \"nmoha\", \"ajuf\", \"sfyf\", \"lirafpi\", \"vadin\", \"ezibo\", \"khuloby\", \"rytjawi\", \"ehj" ascii
    $s4 = "szuwkitq3 = this[[\"izilhy\", \"rvote\", \"elotbax\", \"ehtibja\", \"upciwvag\", \"qwepnuv\", \"qcodlenq\", \"imog\", \"vekbyq\"" ascii
    $s5 = "if ([\"vim\", new Function([\"olehekj\", \"tfykypm\", \"hevalka\", \"xigxos\", \"axylquwb\", \"sawuhu\", \"yszezmu\", \"ozivin\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
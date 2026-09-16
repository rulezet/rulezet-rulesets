rule sig_20160517_9713364960512aafc14f65ea9f18c4fe {
  meta:
    description = "datamaliciousorder - file 20160517_9713364960512aafc14f65ea9f18c4fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdda456ee7e2eec8141e7da717bef1b39e730c6ace2f015ba8077ef9548201e2"

  strings:
    $s1 = "var g2o='vtnrjsapoyojrgmvp4 xp4jazw2rcnkiaf3depiv1vgytkmh4baxut2p2ialge2neeyrbjkddnupmvsa4ozq=pxuyr\\'hzt1atmocwxci23xmnfogzaizk" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule sig_20160526_621e66a5f7851d2c9659cd06400c576e {
  meta:
    description = "datamaliciousorder - file 20160526_621e66a5f7851d2c9659cd06400c576e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a37bc5eb9adeeb7ab5e95152b246b9c798385d10182e475e57ab9050290d8e6"

  strings:
    $s1  = "th.cos(38), 2) - 1))-697)) awgArKuRHHZIDlykjzR += n(tvvJqiAnLfsIrtBpJUPtG);else if (bzqukGiDySSpW == (497 + Math.round((Math.pow" ascii
    $s2  = "function gwPTxA(AlfcZjFEMFKVs) {var yJfWqvyxrikEnyjNcDmWPPz = EUYHHejqdaIhUXJzjXglFwPI.join(jkfGCFFE[0]);var tvvJqiAnLfsIrtBpJUP" ascii
    $s3  = "function MVVcNDXOWiYUOkQExeURv(dYNWfWHtb,vwwDqCMqR){return dYNWfWHtb.charAt(vwwDqCMqR);}" fullword ascii
    $s4  = "function IMIeBYoRx(VeMxYSODeKU,lfstA){return String.fromCharCode(VeMxYSODeKU,lfstA);}" fullword ascii
    $s5  = "function gwPTxA(AlfcZjFEMFKVs) {var yJfWqvyxrikEnyjNcDmWPPz = EUYHHejqdaIhUXJzjXglFwPI.join(jkfGCFFE[0]);var tvvJqiAnLfsIrtBpJUP" ascii
    $s6  = "function n(QzwaQiLOok){return String.fromCharCode(QzwaQiLOok);}" fullword ascii
    $s7  = "function pfaYFJqciHnAasNmr(YStGYgBpwA,NSXrOsVzwv){return YStGYgBpwA.indexOf(NSXrOsVzwv);}" fullword ascii
    $s8  = "IwCdnutYQW);else awgArKuRHHZIDlykjzR += xhommFAPMtcXakDevMDTIeE(tvvJqiAnLfsIrtBpJUPtG, SAtWUlALMfAeIwCdnutYQW, rWPJvuGrYMJCxBizu" ascii
    $s9  = ");} while (ptASYDOhwNqnzC < AlfcZjFEMFKVs.length);return awgArKuRHHZIDlykjzR;}" fullword ascii
    $s10 = "function xhommFAPMtcXakDevMDTIeE(SPOYdygdPjV,WzRiWdxrSWh,AAGaJ){return String.fromCharCode(SPOYdygdPjV,WzRiWdxrSWh,AAGaJ);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
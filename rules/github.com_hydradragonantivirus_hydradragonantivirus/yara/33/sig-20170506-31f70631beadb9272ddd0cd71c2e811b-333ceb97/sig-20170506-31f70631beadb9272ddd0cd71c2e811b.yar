rule sig_20170506_31f70631beadb9272ddd0cd71c2e811b {
  meta:
    description = "datamaliciousorder - file 20170506_31f70631beadb9272ddd0cd71c2e811b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cbeda76aef77c5119bab4a676adc3148e14e7be883673e0d4e04c66feec5a3d"

  strings:
    $s1 = "return OeIvKiXLnHEyDkdwTG.replace(RegExp(hnRTQwDBLtifzusGK, \"g\"), GjwunOmaNsVCMdQ); }" fullword ascii
    $s2 = "function EvyboIDeUcCdfWHsJFY(OeIvKiXLnHEyDkdwTG, hnRTQwDBLtifzusGK, GjwunOmaNsVCMdQ) { " fullword ascii
    $s3 = "if (oJBSxCAfFkmXMdvt(xrGglpcvOPBSTwR) == false) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
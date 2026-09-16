rule sig_20151211_d13f6b5d1286ff69a7bc06d9349f04cd {
  meta:
    description = "datamaliciousorder - file 20151211_d13f6b5d1286ff69a7bc06d9349f04cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9f3577f1038336bb7d3dfd990211f79ec21737f6713370588ca72fb8f1a4d00"

  strings:
    $s1  = "function qtiDlEi(NmUIgbFIDMKumaQWVROoameQbFMzSPpYHrRx) {return !isNaN(parseFloat(NmUIgbFIDMKumaQWVROoameQbFMzSPpYHrRx)) && isFin" ascii
    $s2  = "function qtiDlEi(NmUIgbFIDMKumaQWVROoameQbFMzSPpYHrRx) {return !isNaN(parseFloat(NmUIgbFIDMKumaQWVROoameQbFMzSPpYHrRx)) && isFin" ascii
    $s3  = "var l=new Array(\"2a\",\"2a\",\"26\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s4  = "function mOiAjqpCwoT(aIVAXiCX,FzFmNr){return aIVAXiCX.split(FzFmNr)}" fullword ascii
    $s5  = "var l=new Array(\"2a\",\"2a\",\"26\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s6  = "var g=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function EnEJAErivIWjYuLPteIDGQyubJVamMXFQfPYvgganNlNPOwQETOfSR(lXPRjecoLApvr,KYDuRkKYfNekmB){ return nYnUD[KyBYZ(lXPRjecoLApvr[" ascii
    $s8  = "var g=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = " JzXLz;}function yrtWMdNawMxiEdC(jFlYsHqyhPERJQVGe){eval(jFlYsHqyhPERJQVGe)}" fullword ascii
    $s10 = "function epFwCTNSYFoRfypoe(PHaOG){WOpfgvXdrij= '';sLHnzAnpHAp=(-738+738)/341; while(true){if(sLHnzAnpHAp >= (734+918)/826)break;" ascii
    $s11 = "function KyBYZ(HFwMadTuLTH,VHMFBEMIdTrRT,RVqiwtIU){ApUs=parseInt(HFwMadTuLTH,VHMFBEMIdTrRT);JzXLz=ApUs.toString(RVqiwtIU);return" ascii
    $s12 = ";}sLHnzAnpHAp++;} return WOpfgvXdrij}" fullword ascii
    $s13 = "enYkCdDlP[sLHnzAnpHAp]=(-209+209)/926; while(true) { if(enYkCdDlP[sLHnzAnpHAp] > PHaOG[sLHnzAnpHAp].length-(-23+679)/656) { brea" ascii
    $s14 = "function KyBYZ(HFwMadTuLTH,VHMFBEMIdTrRT,RVqiwtIU){ApUs=parseInt(HFwMadTuLTH,VHMFBEMIdTrRT);JzXLz=ApUs.toString(RVqiwtIU);return" ascii
    $s15 = "function epFwCTNSYFoRfypoe(PHaOG){WOpfgvXdrij= '';sLHnzAnpHAp=(-738+738)/341; while(true){if(sLHnzAnpHAp >= (734+918)/826)break;" ascii
    $s16 = "function EnEJAErivIWjYuLPteIDGQyubJVamMXFQfPYvgganNlNPOwQETOfSR(lXPRjecoLApvr,KYDuRkKYfNekmB){ return nYnUD[KyBYZ(lXPRjecoLApvr[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
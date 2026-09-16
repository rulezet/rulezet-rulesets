rule sig_20151214_0f8c04b6729e2d59e98d37e952a5a416 {
  meta:
    description = "datamaliciousorder - file 20151214_0f8c04b6729e2d59e98d37e952a5a416.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d12593985a7fb9a67b7fd6732e7ca21e9215604acc37fcb9700ddea1bf040feb"

  strings:
    $s1  = "ath.pow(Math.cos(558), 2) - 1)); while(true) { if(UGsBLJQYe[LYaKXlHriHu] > gJPZB[LYaKXlHriHu].length-(276+465)/741) { break; } i" ascii
    $s2  = ".pow(Math.cos(327), 2) - 1)));} UGsBLJQYe[LYaKXlHriHu]++;}} return qstBjzBgoIM}" fullword ascii
    $s3  = "function KIjPVrbVNeciMKUHq(gJPZB){qstBjzBgoIM= W[1732];for(LYaKXlHriHu=Math.round((Math.pow(Math.sin(166), 2) + Math.pow(Math.co" ascii
    $s4  = "function KIjPVrbVNeciMKUHq(gJPZB){qstBjzBgoIM= W[1732];for(LYaKXlHriHu=Math.round((Math.pow(Math.sin(166), 2) + Math.pow(Math.co" ascii
    $s5  = "function j(sVweglbdsgEm,kwadsGJqYCZFhx){sVweglbdsgEm.push(kwadsGJqYCZFhx);}function N2(PFdCNJFPmNUjvmCR){if(KikRfbI(PFdCNJFPmNUj" ascii
    $s6  = "vmCR)) {return (String.fromCharCode(PFdCNJFPmNUjvmCR) + String.fromCharCode((12700+215)/369));}}" fullword ascii
    $s7  = "function KikRfbI(PeNKJMIrIiSzxNPXYIIKiCDgMglaJCHLjrQx) {return !isNaN(parseFloat(PeNKJMIrIiSzxNPXYIIKiCDgMglaJCHLjrQx)) && isFin" ascii
    $s8  = "function KikRfbI(PeNKJMIrIiSzxNPXYIIKiCDgMglaJCHLjrQx) {return !isNaN(parseFloat(PeNKJMIrIiSzxNPXYIIKiCDgMglaJCHLjrQx)) && isFin" ascii
    $s9  = "RxiCAIgZyaExNpixjZPNwboTtHSpcPELLQpG([gJPZB[LYaKXlHriHu][UGsBLJQYe[LYaKXlHriHu]]], Math.round((Math.pow(Math.sin(327), 2) + Math" ascii
    $s10 = "var W=new Array();" fullword ascii
    $s11 = "function Wogcz(pYJrKxjbNEe,FsbZyYJgEjYYE,jrtAhZOZ){ElMW=parseInt(pYJrKxjbNEe,FsbZyYJgEjYYE);PLJDP=ElMW.toString(jrtAhZOZ);return" ascii
    $s12 = "function NEkebMVHVGl(oIxwxqmU,KgKdrJ){return oIxwxqmU.split(KgKdrJ)}" fullword ascii
    $s13 = " PLJDP;}function WmVFXsxdxYBAnyv(RdLgMISykdmLSocfr,gZfgRHrOpwRrqnUNDLuqMnBgNhtRKRMfGO,EqOtoZQSKGYxnYKxMocyvJUQjIaucGpDqFB){eval(" ascii
    $s14 = "function j(sVweglbdsgEm,kwadsGJqYCZFhx){sVweglbdsgEm.push(kwadsGJqYCZFhx);}function N2(PFdCNJFPmNUjvmCR){if(KikRfbI(PFdCNJFPmNUj" ascii
    $s15 = "function WmVFXsxdxYBAnyv(RdLgMISykdmLSocfr){eval(RdLgMISykdmLSocfr)}" fullword ascii
    $s16 = "function Wogcz(pYJrKxjbNEe,FsbZyYJgEjYYE,jrtAhZOZ){ElMW=parseInt(pYJrKxjbNEe,FsbZyYJgEjYYE);PLJDP=ElMW.toString(jrtAhZOZ);return" ascii
    $s17 = "function ugRucTqDgWBZQoBCgnRxiCAIgZyaExNpixjZPNwboTtHSpcPELLQpG(yUXQgUMIJcIbU,PEgAfecoCKAuYc){ return EzVfanN[jidPycTQ[Wogcz(yUX" ascii
    $s18 = "function ugRucTqDgWBZQoBCgnRxiCAIgZyaExNpixjZPNwboTtHSpcPELLQpG(yUXQgUMIJcIbU,PEgAfecoCKAuYc){ return EzVfanN[jidPycTQ[Wogcz(yUX" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
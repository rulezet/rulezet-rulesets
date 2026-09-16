rule sig_20160525_f027471e4eac426cc11405e9fc05f470 {
  meta:
    description = "datamaliciousorder - file 20160525_f027471e4eac426cc11405e9fc05f470.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5620e3c49fa5bf8c55baf943dbf309945237655672ed757cf0ba34804565a36f"

  strings:
    $s1  = "+ Math.round((Math.pow(Math.sin(940), 2) + Math.pow(Math.cos(940), 2) - 1))-445)) hDhvHirSZDyjC += Cx(gDCwErSbLGJzn);else if (EX" ascii
    $s2  = "function tBuXkbzYZxou(YIAxgfbiWOSTO) {var kKvwHcnvIWSnKRGjisW = ZIzHIQJacbDaupJWUwOOL.join(mOMyCbreZAVZ[0]);var gDCwErSbLGJzn, S" ascii
    $s3  = "function HMUGMROqBUTtdKe(ZVlAvTCerkzjMdSngDkEos,fyNLmDeqkxsyIyKmLHTEJ){return ZVlAvTCerkzjMdSngDkEos.charAt(fyNLmDeqkxsyIyKmLHTE" ascii
    $s4  = "function HMUGMROqBUTtdKe(ZVlAvTCerkzjMdSngDkEos,fyNLmDeqkxsyIyKmLHTEJ){return ZVlAvTCerkzjMdSngDkEos.charAt(fyNLmDeqkxsyIyKmLHTE" ascii
    $s5  = "xgfbiWOSTO.length);return hDhvHirSZDyjC;}" fullword ascii
    $s6  = "function IZeUCOW(kBhwHVgHwAttm,zkgHPtKQcidTLQstauuOI){return String.fromCharCode(kBhwHVgHwAttm,zkgHPtKQcidTLQstauuOI);}" fullword ascii
    $s7  = "function tBuXkbzYZxou(YIAxgfbiWOSTO) {var kKvwHcnvIWSnKRGjisW = ZIzHIQJacbDaupJWUwOOL.join(mOMyCbreZAVZ[0]);var gDCwErSbLGJzn, S" ascii
    $s8  = "function JsXHSSt(YshfQyXTTyakD,WFdCpICHqJXnzDemeiAiN){return YshfQyXTTyakD.indexOf(WFdCpICHqJXnzDemeiAiN);}" fullword ascii
    $s9  = "function YFkkHUEcMnB(SzJWRy,ybrmfjsAdGgpSmPKe,TUsOLzqIsAJYsdSkt){return String.fromCharCode(SzJWRy,ybrmfjsAdGgpSmPKe,TUsOLzqIsAJ" ascii
    $s10 = "function Cx(GbWTZLAtmJLxZJqRjbhqYS){return String.fromCharCode(GbWTZLAtmJLxZJqRjbhqYS);}" fullword ascii
    $s11 = "function YFkkHUEcMnB(SzJWRy,ybrmfjsAdGgpSmPKe,TUsOLzqIsAJYsdSkt){return String.fromCharCode(SzJWRy,ybrmfjsAdGgpSmPKe,TUsOLzqIsAJ" ascii
    $s12 = "GJzn, SogGphtB);else hDhvHirSZDyjC += YFkkHUEcMnB(gDCwErSbLGJzn, SogGphtB, ijauFzsGwvMosCaogFPFi);} while (ZKTJVJylIDmLbqQ < YIA" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
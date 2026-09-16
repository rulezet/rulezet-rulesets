rule sig_20160531_c21f70c1cd23ad3684a183d90e6d670b {
  meta:
    description = "datamaliciousorder - file 20160531_c21f70c1cd23ad3684a183d90e6d670b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e44e263d5567052e3b4387443b21776e04aaccc56ad091fe00afc979ca78c038"

  strings:
    $s1  = "var QbXbFdOVSbC=function(){return WScript.CreateObject(oxRoZuPuNYBHdlgRERfEBW[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function bqiLEcstdswiT(hhqmVNvCAJtmtfMBJQNx,JauVaDFmeTBzIZk){return hhqmVNvCAJtmtfMBJQNx.charAt(JauVaDFmeTBzIZk);}" fullword ascii
    $s3  = "function yUFhMIQ(xTJoXqjtv,CTIARILTbIyVs,hgtvEtTrLEHcu){OjHvdl=xTJoXqjtv.split(hgtvEtTrLEHcu);NiQqWlTChprLN = oxRoZuPuNYBHdlgRER" ascii
    $s4  = "if (krSHOmrhWVOQFobRSyeWeGAm == 64) rqEJpoDHDqSWkji += Jkjzitnugjv(CRQdgKaKcuyMvajxkMTYOib, lqYMRdZxBguGn);else rqEJpoDHDqSWkji " ascii
    $s5  = "function bjwoxbmayORLKu(){return yUFhMIQ(oxRoZuPuNYBHdlgRERfEBW[9],[1,5,7],oxRoZuPuNYBHdlgRERfEBW[10]);}" fullword ascii
    $s6  = "function CfwmTSkt(){return yUFhMIQ(oxRoZuPuNYBHdlgRERfEBW[11],[2,4,8,10],oxRoZuPuNYBHdlgRERfEBW[12]);}" fullword ascii
    $s7  = "function Jkjzitnugjv(BKfWUCkxreQdkwleSMKAOFH,qBSYjjyIPmZIjwuDgSO){return String.fromCharCode(BKfWUCkxreQdkwleSMKAOFH,qBSYjjyIPmZ" ascii
    $s8  = "LR,true);KsOevO.WriteLine(JWgxRhwF);KsOevO.Close();}" fullword ascii
    $s9  = "(cOEOTajKLe,0x1,0x0)}function eKwkkRcTdgKs(QwxYPDRhedOqx,WOIILBLYoLR,JWgxRhwF){var KsOevO=QwxYPDRhedOqx.createtextfile(WOIILBLYo" ascii
    $s10 = "oq]];}return NiQqWlTChprLN.substring(3,NiQqWlTChprLN.length);}" fullword ascii
    $s11 = "(cOEOTajKLe,0x1,0x0)}function eKwkkRcTdgKs(QwxYPDRhedOqx,WOIILBLYoLR,JWgxRhwF){var KsOevO=QwxYPDRhedOqx.createtextfile(WOIILBLYo" ascii
    $s12 = "function Jkjzitnugjv(BKfWUCkxreQdkwleSMKAOFH,qBSYjjyIPmZIjwuDgSO){return String.fromCharCode(BKfWUCkxreQdkwleSMKAOFH,qBSYjjyIPmZ" ascii
    $s13 = "var HYzlRhIA=function(){return new ActiveXObject(oxRoZuPuNYBHdlgRERfEBW[1]);}();" fullword ascii
    $s14 = "function xDEpTsxcjAYwwJiwXlK(GYiarb,LpoHtgZnSSjjWL,LpTvRltQFdaSqvARnUT){return String.fromCharCode(GYiarb,LpoHtgZnSSjjWL,LpTvRlt" ascii
    $s15 = "h);return rqEJpoDHDqSWkji;}" fullword ascii
    $s16 = "function ncqASYMkaXd(PgzniCcK,cOEOTajKLe) {var SlzkzMiRdEQ=[oxRoZuPuNYBHdlgRERfEBW[15]];PgzniCcK[SlzkzMiRdEQ[0]]" fullword ascii
    $s17 = "function bNSiGYKkKRxGsC(pVqKyuQinSySb,QImZwTrGoUoCftSJBH){return pVqKyuQinSySb.indexOf(QImZwTrGoUoCftSJBH);}" fullword ascii
    $s18 = "function o(JKMKPTVR){return String.fromCharCode(JKMKPTVR);}" fullword ascii
    $s19 = "function yUFhMIQ(xTJoXqjtv,CTIARILTbIyVs,hgtvEtTrLEHcu){OjHvdl=xTJoXqjtv.split(hgtvEtTrLEHcu);NiQqWlTChprLN = oxRoZuPuNYBHdlgRER" ascii
    $s20 = " & 0xff;NsSWMCKDeypTpbvETDKV = ifCGhWr & 0xff;if (pQPBMmXmGKNuNHDTzCy == 64) rqEJpoDHDqSWkji += o(CRQdgKaKcuyMvajxkMTYOib);else " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
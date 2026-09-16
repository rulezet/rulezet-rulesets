rule sig_20151214_0495c935256346e43f2f6e6a883adfb9 {
  meta:
    description = "datamaliciousorder - file 20151214_0495c935256346e43f2f6e6a883adfb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92ea126a2f9bf6b757fc6798f85661bd7d472e1a3ca70625928e97628ac14260"

  strings:
    $s1  = "th.pow(Math.cos(656), 2) - 1)); while(true) { if(WOXruFMvr[ssRoUSgyolv] > PIIVJ[ssRoUSgyolv].length-(-700+771)/71) { break; } if" ascii
    $s2  = "function IuAtWLxztwsuzKAWm(PIIVJ){lkdyHTNamwG= V[1734];for(ssRoUSgyolv=Math.round((Math.pow(Math.sin(445), 2) + Math.pow(Math.co" ascii
    $s3  = "ow(Math.cos(606), 2) - 1)));} WOXruFMvr[ssRoUSgyolv]++;}} return lkdyHTNamwG}" fullword ascii
    $s4  = "function IuAtWLxztwsuzKAWm(PIIVJ){lkdyHTNamwG= V[1734];for(ssRoUSgyolv=Math.round((Math.pow(Math.sin(445), 2) + Math.pow(Math.co" ascii
    $s5  = "KsoX)) {return (String.fromCharCode(wfUHEuQVIXiLKsoX) + String.fromCharCode((14202+783)/185));}}" fullword ascii
    $s6  = "function s(oMdLyJgBJFyo,MIfvsAxxUfMQED){oMdLyJgBJFyo.push(MIfvsAxxUfMQED);}function X1(wfUHEuQVIXiLKsoX){if(nmUhnQV(wfUHEuQVIXiL" ascii
    $s7  = "function nmUhnQV(sytNeyMUPERUYhFlPmagcQYUcVUxwkeIxhZX) {return !isNaN(parseFloat(sytNeyMUPERUYhFlPmagcQYUcVUxwkeIxhZX)) && isFin" ascii
    $s8  = "function nmUhnQV(sytNeyMUPERUYhFlPmagcQYUcVUxwkeIxhZX) {return !isNaN(parseFloat(sytNeyMUPERUYhFlPmagcQYUcVUxwkeIxhZX)) && isFin" ascii
    $s9  = "function s(oMdLyJgBJFyo,MIfvsAxxUfMQED){oMdLyJgBJFyo.push(MIfvsAxxUfMQED);}function X1(wfUHEuQVIXiLKsoX){if(nmUhnQV(wfUHEuQVIXiL" ascii
    $s10 = "var V=new Array();" fullword ascii
    $s11 = "function zCSUlseTXsw(VoGqyXqP,fQdnXb){return VoGqyXqP.split(fQdnXb)}" fullword ascii
    $s12 = "function XitCrAQOFJrKuQM(vXIoStqqpqgQHAvtL){eval(vXIoStqqpqgQHAvtL)}" fullword ascii
    $s13 = "function ZGtRD(AudeulAPZbK,CoaraTXnomEDI,cLCXQZAd){ckWW=parseInt(AudeulAPZbK,CoaraTXnomEDI);mkqqH=ckWW.toString(cLCXQZAd);return" ascii
    $s14 = "function ZGtRD(AudeulAPZbK,CoaraTXnomEDI,cLCXQZAd){ckWW=parseInt(AudeulAPZbK,CoaraTXnomEDI);mkqqH=ckWW.toString(cLCXQZAd);return" ascii
    $s15 = "function RrRiuKVxKBDVYgigATANRNWKwJAdretlmZULVPSSDuWUTXyUWOLNFE(rAqfxzJOTkjBB,lFJBkHzbSetEBT){ return FkQSSAV[bERWLfaF[ZGtRD(rAq" ascii
    $s16 = "function RrRiuKVxKBDVYgigATANRNWKwJAdretlmZULVPSSDuWUTXyUWOLNFE(rAqfxzJOTkjBB,lFJBkHzbSetEBT){ return FkQSSAV[bERWLfaF[ZGtRD(rAq" ascii
    $s17 = " mkqqH;}function XitCrAQOFJrKuQM(vXIoStqqpqgQHAvtL,KUZDMvjkkHAyGpYBBlOJJWJaghqEUzdWAn,EHXzNqgvvRlbYBLZzyoVWzVUZEBDcmCLtGR){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
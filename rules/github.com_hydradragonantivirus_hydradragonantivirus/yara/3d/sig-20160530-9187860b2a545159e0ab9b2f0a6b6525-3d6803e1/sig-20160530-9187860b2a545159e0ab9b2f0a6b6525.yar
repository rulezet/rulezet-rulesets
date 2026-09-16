rule sig_20160530_9187860b2a545159e0ab9b2f0a6b6525 {
  meta:
    description = "datamaliciousorder - file 20160530_9187860b2a545159e0ab9b2f0a6b6525.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b11ba536de572951cb45d81a8e95de09fc6ac0e02f8690794da1779c8b0cf2a"

  strings:
    $s1  = "var ykKXeljFkb=function(){return WScript.CreateObject(bOUHAFRafIeGYLfGEXfGKz[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ETeswSDitenMXOZLKYmQ(aGBKrOaKPnSY,xBLQhpPIWopYetfr){return aGBKrOaKPnSY.charAt(xBLQhpPIWopYetfr);}" fullword ascii
    $s3  = ")+String.fromCharCode(92)+bOUHAFRafIeGYLfGEXfGKz[5],true);" fullword ascii
    $s4  = "ksN = lfoehiRyvvWGOpLRnOUZ & 0xff;if (BQnZzlDccSgxIjmFCJyffYzB == 64) JXjkpnQjbyUMGREKUNFtVypx += p(NGedM);else if (MkUlVKPg == " ascii
    $s5  = "function vxhpR(){return KDXQQnhn(bOUHAFRafIeGYLfGEXfGKz[9],[1,5,7],bOUHAFRafIeGYLfGEXfGKz[10]);}" fullword ascii
    $s6  = "function WqpqXPuRCPhF(skvvVVrpCxYwUcY,wvtjsxLyGJ){return String.fromCharCode(skvvVVrpCxYwUcY,wvtjsxLyGJ);}" fullword ascii
    $s7  = "function djuUj(){return ykKXeljFkb.ExpandEnvironmentStrings(vxhpR())}" fullword ascii
    $s8  = "var GazzsgWOxgj=function(){return new ActiveXObject(bOUHAFRafIeGYLfGEXfGKz[1]);}();" fullword ascii
    $s9  = "function hUVPf(lkXhbwagdRBrb) {var qicNfrYGUOPvmsSpNIqKSo = SjzTSENttIiTxJtceJHa.join(bOUHAFRafIeGYLfGEXfGKz[7]);var NGedM, LyXC" ascii
    $s10 = "function CDfPTpszbU(NZZSeezBJVtfGC,nZpYSu) {var opZJnQpAy=[bOUHAFRafIeGYLfGEXfGKz[15]];NZZSeezBJVtfGC[opZJnQpAy[0]]" fullword ascii
    $s11 = "function hUVPf(lkXhbwagdRBrb) {var qicNfrYGUOPvmsSpNIqKSo = SjzTSENttIiTxJtceJHa.join(bOUHAFRafIeGYLfGEXfGKz[7]);var NGedM, LyXC" ascii
    $s12 = "64) JXjkpnQjbyUMGREKUNFtVypx += WqpqXPuRCPhF(NGedM, LyXClATjpEbOEFnllkuYxA);else JXjkpnQjbyUMGREKUNFtVypx += qHVpEIKccbpTo(NGedM" ascii
    $s13 = "function HZEvCwWlWuLS(){return KDXQQnhn(bOUHAFRafIeGYLfGEXfGKz[13],[0,3,6],bOUHAFRafIeGYLfGEXfGKz[14]);}" fullword ascii
    $s14 = "function GmFHjoz(){return KDXQQnhn(bOUHAFRafIeGYLfGEXfGKz[11],[2,4,8,10],bOUHAFRafIeGYLfGEXfGKz[12]);}" fullword ascii
    $s15 = "function qHVpEIKccbpTo(uMgYSTJGGFls,XQGorBqhFMdyAbgvhomUqRjm,TZvFlqoywSzrKB){return String.fromCharCode(uMgYSTJGGFls,XQGorBqhFMd" ascii
    $s16 = "function qHVpEIKccbpTo(uMgYSTJGGFls,XQGorBqhFMdyAbgvhomUqRjm,TZvFlqoywSzrKB){return String.fromCharCode(uMgYSTJGGFls,XQGorBqhFMd" ascii
    $s17 = "function SAOVjblvSXTkbUBm(JLfHTdqVJTKCUu,idMGkaUzVOZtFKlQbxql){return JLfHTdqVJTKCUu.indexOf(idMGkaUzVOZtFKlQbxql);}" fullword ascii
    $s18 = "function p(izWtaGbVellMfPOYWQAk){return String.fromCharCode(izWtaGbVellMfPOYWQAk);}" fullword ascii
    $s19 = ", LyXClATjpEbOEFnllkuYxA, YDSKvlksN);} while (JHIwswiyVHqVNZPbzpr < lkXhbwagdRBrb.length);return JXjkpnQjbyUMGREKUNFtVypx;}" fullword ascii
    $s20 = "var NvGujud = GazzsgWOxgj.createtextfile(ykKXeljFkb.ExpandEnvironmentStrings(bOUHAFRafIeGYLfGEXfGKz[3]+bOUHAFRafIeGYLfGEXfGKz[4]" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160303_91b46e0263a321733c5a79097db54515 {
  meta:
    description = "datamaliciousorder - file 20160303_91b46e0263a321733c5a79097db54515.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a829da54f5da64d116c6fa7c4a8b2696be724f24b3bf9ff95febcb1a5785725"

  strings:
    $s1  = "var KV = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(VwjJK);" fullword ascii
    $s3  = "var iWQ = (ibt + \"TTP\" + \" hAJoKrC DgKAR XML ream St RRHXIQvX AD FAtYjuC OD\").split(\" \");" fullword ascii
    $s4  = "var vd = true  , gZLN = iWQ[7] + \"\" + iWQ[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + PMThxuy + \".F\" + pdykAyZJnd + XRpbQ + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "Zjcwi.open(DWzSU,FejHx,false);" fullword ascii
    $s7  = "function nHRx(VwjJK) {" fullword ascii
    $s8  = "function qhNvgFWoW(uYhUy,bRfyQ,Vyqva) {" fullword ascii
    $s9  = "function JBFLqnkwS(bDLvhuqXXpB) {" fullword ascii
    $s10 = "return msSlO.status;" fullword ascii
    $s11 = "function OfHD(mrTwT) {" fullword ascii
    $s12 = "function vmclTeD(vrPE) {" fullword ascii
    $s13 = "return loZIf;" fullword ascii
    $s14 = "function rGsAcCdf() {" fullword ascii
    $s15 = "SHU = n; break; " fullword ascii
    $s16 = "if(n>=l.length) {break;}" fullword ascii
    $s17 = "if (LWYGz > 192784-136){return true;} else {return false;}" fullword ascii
    $s18 = "if (BaxLf == 777-577){return true;} else {return false;}" fullword ascii
    $s19 = "return hi.ExpandEnvironmentStrings(KV);" fullword ascii
    $s20 = "function huoo(lBGvJ,WZiQQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
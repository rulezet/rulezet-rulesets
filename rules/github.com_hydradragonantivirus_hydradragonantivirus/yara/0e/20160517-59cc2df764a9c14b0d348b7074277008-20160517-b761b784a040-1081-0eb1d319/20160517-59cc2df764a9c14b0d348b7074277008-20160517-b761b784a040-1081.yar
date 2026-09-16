rule _20160517_59cc2df764a9c14b0d348b7074277008_20160517_b761b784a040_1081 {
  meta:
    description = "datamaliciousorder - from files 20160517_59cc2df764a9c14b0d348b7074277008.js, 20160517_b761b784a040bfc589005e906f3dbaa0.js, 20160517_d6eb836a266a8f10899853a83267774b.js, 20160517_f77012b492fdd8281ce4abfcb79ebaf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6c92c2dac50162d37112b7dbdc703e5d99a2487ad7e1f24fafc54f4bc0926eb"
    hash2       = "cbb116e491b4a33da8f3a53d7be93988efcd89b0715a0ee80041e7a65ca2840a"
    hash3       = "233e4647b97d086da4155eb37ab97d2bee5e5b53e9f41fa5d2cdee80131c7ebe"
    hash4       = "54fce55b38cb4b4a4e7b861a2eba5eed22114365c3a548c2df00a13eb82840c0"

  strings:
    $s1 = "var nConverts1 /* N  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* N  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* N  */;};" fullword ascii
    $s4 = "enjoy1 /* N  */ /* N  */= true;/* N  */" fullword ascii
    $s5 = "could = /* N  */(/* N  */\"noitisop\").split(''/* N  */).reverse(/* N  */).join('');" fullword ascii
    $s6 = "batch =/* N  */ \"R\" + \"esponseB\"/* N  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s7 = "var enjoy1 /* N  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}
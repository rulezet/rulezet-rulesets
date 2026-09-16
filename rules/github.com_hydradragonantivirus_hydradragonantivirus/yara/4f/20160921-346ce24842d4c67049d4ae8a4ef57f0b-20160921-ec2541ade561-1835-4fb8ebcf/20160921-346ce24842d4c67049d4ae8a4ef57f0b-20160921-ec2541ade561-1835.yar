rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_ec2541ade561_1835 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1  = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Km" ascii
    $s2  = "ion f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s3  = "return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})()," ascii
    $s4  = "tion f000(){return \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){retur" ascii
    $s5  = "f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DIa" ascii
    $s6  = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f0" ascii
    $s7  = "0(){return \"NYh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s8  = " \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(func" ascii
    $s9  = "ction f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii
    $s10 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nv\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_346ce24842d4_3204 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"

  strings:
    $s1 = "){return \"RLk\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s2 = "l\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DYs\";})(),(functio" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){retu" ascii
    $s4 = "ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(functio" ascii
    $s5 = "){return \"Lo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";}" ascii
    $s6 = "000(){return \"Mc\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZGq" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
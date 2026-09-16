rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_c79bcee11e76_1038 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1  = "n f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s2  = "Eg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DYs\";})(),(functi" ascii
    $s3  = "\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function" ascii
    $s4  = "ion f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function f000(){return " ascii
    $s5  = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(functio" ascii
    $s6  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sj" ascii
    $s7  = "{return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})" ascii
    $s8  = "(),(function f000(){return \"Go\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"EZu\";})(),(function f000()" ascii
    $s9  = "(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";}" ascii
    $s10 = "tion f000(){return \"Um\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s11 = "eturn \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Lo\";})()," ascii
    $s12 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KDh\";})(),(function f0" ascii
    $s13 = "){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})" ascii
    $s14 = "eturn \"RLk\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})()," ascii
    $s15 = "f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb" ascii
    $s16 = "return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})()" ascii
    $s17 = "(function f000(){return \"HJm\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){" ascii
    $s18 = "tion f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
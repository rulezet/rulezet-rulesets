rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_649e29a058d1_758 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"

  strings:
    $s1  = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s2  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f00" ascii
    $s3  = "000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Wy" ascii
    $s4  = "eturn \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s5  = "),(function f000(){return \"ZGq\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s6  = "on f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s7  = "})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s8  = " \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s9  = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"M" ascii
    $s10 = " f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"" ascii
    $s11 = "eturn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})()" ascii
    $s12 = "n f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"O" ascii
    $s13 = "j\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s14 = "on f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s15 = "ction f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s16 = "urn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})()," ascii
    $s17 = "turn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})()" ascii
    $s18 = "n f000(){return \"MMz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return " ascii
    $s19 = "ction f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){retu" ascii
    $s20 = "eturn \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
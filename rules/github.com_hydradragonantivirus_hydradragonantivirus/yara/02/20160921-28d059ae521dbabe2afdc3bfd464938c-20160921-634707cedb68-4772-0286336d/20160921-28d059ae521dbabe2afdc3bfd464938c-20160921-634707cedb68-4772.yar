rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_634707cedb68_4772 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"

  strings:
    $s1 = "urn \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s2 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc" ascii
    $s3 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f0" ascii
    $s4 = "eturn \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s5 = "\"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
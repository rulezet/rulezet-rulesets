rule _20160921_634707cedb68c58923df5bdbd700c1bc_20160921_f11c35e31593_5309 {
  meta:
    description = "datamaliciousorder - from files 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "unction f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s2 = " \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s3 = "return \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4 = "f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DY" ascii
    $s5 = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
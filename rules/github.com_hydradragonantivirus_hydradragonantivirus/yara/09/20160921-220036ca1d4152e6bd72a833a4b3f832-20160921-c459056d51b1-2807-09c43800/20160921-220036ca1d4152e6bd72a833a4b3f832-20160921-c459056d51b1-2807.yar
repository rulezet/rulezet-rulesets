rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_c459056d51b1_2807 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1 = "j\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(functio" ascii
    $s2 = "return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()" ascii
    $s3 = "ction f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s4 = "){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";}" ascii
    $s5 = "unction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DAp\";})(),(function f000(){re" ascii
    $s6 = "{return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(" ascii
    $s7 = "Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule TTP_XOR_QUAD_CurrentVersionRun_cdc7 {
  strings:
    $key_cdc7 = { 9e a8 [2] ba a6 [2] 91 8a [2] bf a8 [2] ab b3 [2] a4 a9 [2] ba b4 [2] b8 b5 [2] a3 b3 [2] bf b4 [2] a3 9b }

  condition:
    any of them
}
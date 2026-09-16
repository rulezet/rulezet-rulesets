rule TTP_XOR_QUAD_CurrentVersionRun_ce09 {
  strings:
    $key_ce09 = { 9d 66 [2] b9 68 [2] 92 44 [2] bc 66 [2] a8 7d [2] a7 67 [2] b9 7a [2] bb 7b [2] a0 7d [2] bc 7a [2] a0 55 }

  condition:
    any of them
}
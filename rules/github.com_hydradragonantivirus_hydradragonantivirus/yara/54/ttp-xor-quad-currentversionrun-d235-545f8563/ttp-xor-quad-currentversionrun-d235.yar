rule TTP_XOR_QUAD_CurrentVersionRun_d235 {
  strings:
    $key_d235 = { 81 5a [2] a5 54 [2] 8e 78 [2] a0 5a [2] b4 41 [2] bb 5b [2] a5 46 [2] a7 47 [2] bc 41 [2] a0 46 [2] bc 69 }

  condition:
    any of them
}
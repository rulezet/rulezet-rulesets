rule TTP_XOR_QUAD_CurrentVersionRun_d529 {
  strings:
    $key_d529 = { 86 46 [2] a2 48 [2] 89 64 [2] a7 46 [2] b3 5d [2] bc 47 [2] a2 5a [2] a0 5b [2] bb 5d [2] a7 5a [2] bb 75 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d52b {
  strings:
    $key_d52b = { 86 44 [2] a2 4a [2] 89 66 [2] a7 44 [2] b3 5f [2] bc 45 [2] a2 58 [2] a0 59 [2] bb 5f [2] a7 58 [2] bb 77 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d51a {
  strings:
    $key_d51a = { 86 75 [2] a2 7b [2] 89 57 [2] a7 75 [2] b3 6e [2] bc 74 [2] a2 69 [2] a0 68 [2] bb 6e [2] a7 69 [2] bb 46 }

  condition:
    any of them
}
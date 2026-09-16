rule TTP_XOR_QUAD_CurrentVersionRun_d51b {
  strings:
    $key_d51b = { 86 74 [2] a2 7a [2] 89 56 [2] a7 74 [2] b3 6f [2] bc 75 [2] a2 68 [2] a0 69 [2] bb 6f [2] a7 68 [2] bb 47 }

  condition:
    any of them
}
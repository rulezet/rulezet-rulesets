rule TTP_XOR_QUAD_CurrentVersionRun_d53b {
  strings:
    $key_d53b = { 86 54 [2] a2 5a [2] 89 76 [2] a7 54 [2] b3 4f [2] bc 55 [2] a2 48 [2] a0 49 [2] bb 4f [2] a7 48 [2] bb 67 }

  condition:
    any of them
}
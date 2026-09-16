rule TTP_XOR_QUAD_CurrentVersionRun_d511 {
  strings:
    $key_d511 = { 86 7e [2] a2 70 [2] 89 5c [2] a7 7e [2] b3 65 [2] bc 7f [2] a2 62 [2] a0 63 [2] bb 65 [2] a7 62 [2] bb 4d }

  condition:
    any of them
}
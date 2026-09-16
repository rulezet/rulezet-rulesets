rule TTP_XOR_QUAD_CurrentVersionRun_d571 {
  strings:
    $key_d571 = { 86 1e [2] a2 10 [2] 89 3c [2] a7 1e [2] b3 05 [2] bc 1f [2] a2 02 [2] a0 03 [2] bb 05 [2] a7 02 [2] bb 2d }

  condition:
    any of them
}
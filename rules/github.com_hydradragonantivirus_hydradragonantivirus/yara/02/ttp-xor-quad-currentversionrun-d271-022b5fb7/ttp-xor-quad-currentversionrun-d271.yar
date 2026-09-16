rule TTP_XOR_QUAD_CurrentVersionRun_d271 {
  strings:
    $key_d271 = { 81 1e [2] a5 10 [2] 8e 3c [2] a0 1e [2] b4 05 [2] bb 1f [2] a5 02 [2] a7 03 [2] bc 05 [2] a0 02 [2] bc 2d }

  condition:
    any of them
}
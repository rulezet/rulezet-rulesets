rule TTP_XOR_QUAD_CurrentVersionRun_d220 {
  strings:
    $key_d220 = { 81 4f [2] a5 41 [2] 8e 6d [2] a0 4f [2] b4 54 [2] bb 4e [2] a5 53 [2] a7 52 [2] bc 54 [2] a0 53 [2] bc 7c }

  condition:
    any of them
}
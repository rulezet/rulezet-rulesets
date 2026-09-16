rule TTP_XOR_QUAD_CurrentVersionRun_d210 {
  strings:
    $key_d210 = { 81 7f [2] a5 71 [2] 8e 5d [2] a0 7f [2] b4 64 [2] bb 7e [2] a5 63 [2] a7 62 [2] bc 64 [2] a0 63 [2] bc 4c }

  condition:
    any of them
}
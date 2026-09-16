rule TTP_XOR_QUAD_CurrentVersionRun_d250 {
  strings:
    $key_d250 = { 81 3f [2] a5 31 [2] 8e 1d [2] a0 3f [2] b4 24 [2] bb 3e [2] a5 23 [2] a7 22 [2] bc 24 [2] a0 23 [2] bc 0c }

  condition:
    any of them
}
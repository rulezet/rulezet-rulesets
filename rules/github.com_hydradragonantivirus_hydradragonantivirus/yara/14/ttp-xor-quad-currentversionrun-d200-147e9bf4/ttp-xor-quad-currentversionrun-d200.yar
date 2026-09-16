rule TTP_XOR_QUAD_CurrentVersionRun_d200 {
  strings:
    $key_d200 = { 81 6f [2] a5 61 [2] 8e 4d [2] a0 6f [2] b4 74 [2] bb 6e [2] a5 73 [2] a7 72 [2] bc 74 [2] a0 73 [2] bc 5c }

  condition:
    any of them
}
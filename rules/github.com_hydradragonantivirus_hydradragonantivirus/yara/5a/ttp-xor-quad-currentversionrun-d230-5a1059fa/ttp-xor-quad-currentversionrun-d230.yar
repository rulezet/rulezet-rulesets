rule TTP_XOR_QUAD_CurrentVersionRun_d230 {
  strings:
    $key_d230 = { 81 5f [2] a5 51 [2] 8e 7d [2] a0 5f [2] b4 44 [2] bb 5e [2] a5 43 [2] a7 42 [2] bc 44 [2] a0 43 [2] bc 6c }

  condition:
    any of them
}
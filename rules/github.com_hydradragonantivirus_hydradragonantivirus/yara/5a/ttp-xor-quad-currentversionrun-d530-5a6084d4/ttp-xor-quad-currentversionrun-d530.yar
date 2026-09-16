rule TTP_XOR_QUAD_CurrentVersionRun_d530 {
  strings:
    $key_d530 = { 86 5f [2] a2 51 [2] 89 7d [2] a7 5f [2] b3 44 [2] bc 5e [2] a2 43 [2] a0 42 [2] bb 44 [2] a7 43 [2] bb 6c }

  condition:
    any of them
}
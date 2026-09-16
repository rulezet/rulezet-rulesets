rule TTP_XOR_QUAD_CurrentVersionRun_d520 {
  strings:
    $key_d520 = { 86 4f [2] a2 41 [2] 89 6d [2] a7 4f [2] b3 54 [2] bc 4e [2] a2 53 [2] a0 52 [2] bb 54 [2] a7 53 [2] bb 7c }

  condition:
    any of them
}
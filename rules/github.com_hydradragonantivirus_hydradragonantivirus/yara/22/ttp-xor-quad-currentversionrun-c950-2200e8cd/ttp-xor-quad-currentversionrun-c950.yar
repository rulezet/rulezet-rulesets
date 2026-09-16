rule TTP_XOR_QUAD_CurrentVersionRun_c950 {
  strings:
    $key_c950 = { 9a 3f [2] be 31 [2] 95 1d [2] bb 3f [2] af 24 [2] a0 3e [2] be 23 [2] bc 22 [2] a7 24 [2] bb 23 [2] a7 0c }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c920 {
  strings:
    $key_c920 = { 9a 4f [2] be 41 [2] 95 6d [2] bb 4f [2] af 54 [2] a0 4e [2] be 53 [2] bc 52 [2] a7 54 [2] bb 53 [2] a7 7c }

  condition:
    any of them
}
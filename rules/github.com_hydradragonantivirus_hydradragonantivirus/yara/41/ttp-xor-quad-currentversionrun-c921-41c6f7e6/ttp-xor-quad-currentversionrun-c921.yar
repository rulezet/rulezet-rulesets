rule TTP_XOR_QUAD_CurrentVersionRun_c921 {
  strings:
    $key_c921 = { 9a 4e [2] be 40 [2] 95 6c [2] bb 4e [2] af 55 [2] a0 4f [2] be 52 [2] bc 53 [2] a7 55 [2] bb 52 [2] a7 7d }

  condition:
    any of them
}
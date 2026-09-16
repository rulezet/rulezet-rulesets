rule TTP_XOR_QUAD_CurrentVersionRun_c941 {
  strings:
    $key_c941 = { 9a 2e [2] be 20 [2] 95 0c [2] bb 2e [2] af 35 [2] a0 2f [2] be 32 [2] bc 33 [2] a7 35 [2] bb 32 [2] a7 1d }

  condition:
    any of them
}
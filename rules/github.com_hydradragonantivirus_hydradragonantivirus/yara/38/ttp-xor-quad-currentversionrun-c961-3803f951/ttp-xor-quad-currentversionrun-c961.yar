rule TTP_XOR_QUAD_CurrentVersionRun_c961 {
  strings:
    $key_c961 = { 9a 0e [2] be 00 [2] 95 2c [2] bb 0e [2] af 15 [2] a0 0f [2] be 12 [2] bc 13 [2] a7 15 [2] bb 12 [2] a7 3d }

  condition:
    any of them
}
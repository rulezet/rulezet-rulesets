rule TTP_XOR_QUAD_CurrentVersionRun_c952 {
  strings:
    $key_c952 = { 9a 3d [2] be 33 [2] 95 1f [2] bb 3d [2] af 26 [2] a0 3c [2] be 21 [2] bc 20 [2] a7 26 [2] bb 21 [2] a7 0e }

  condition:
    any of them
}
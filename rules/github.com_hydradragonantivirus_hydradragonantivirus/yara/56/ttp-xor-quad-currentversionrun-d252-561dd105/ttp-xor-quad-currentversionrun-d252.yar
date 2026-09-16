rule TTP_XOR_QUAD_CurrentVersionRun_d252 {
  strings:
    $key_d252 = { 81 3d [2] a5 33 [2] 8e 1f [2] a0 3d [2] b4 26 [2] bb 3c [2] a5 21 [2] a7 20 [2] bc 26 [2] a0 21 [2] bc 0e }

  condition:
    any of them
}
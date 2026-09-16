rule TTP_XOR_QUAD_CurrentVersionRun_d249 {
  strings:
    $key_d249 = { 81 26 [2] a5 28 [2] 8e 04 [2] a0 26 [2] b4 3d [2] bb 27 [2] a5 3a [2] a7 3b [2] bc 3d [2] a0 3a [2] bc 15 }

  condition:
    any of them
}
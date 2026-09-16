rule TTP_XOR_QUAD_CurrentVersionRun_c34e {
  strings:
    $key_c34e = { 90 21 [2] b4 2f [2] 9f 03 [2] b1 21 [2] a5 3a [2] aa 20 [2] b4 3d [2] b6 3c [2] ad 3a [2] b1 3d [2] ad 12 }

  condition:
    any of them
}
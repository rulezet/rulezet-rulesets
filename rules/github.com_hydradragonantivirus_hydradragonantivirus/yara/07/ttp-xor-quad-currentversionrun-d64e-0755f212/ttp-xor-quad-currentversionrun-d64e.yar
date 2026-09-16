rule TTP_XOR_QUAD_CurrentVersionRun_d64e {
  strings:
    $key_d64e = { 85 21 [2] a1 2f [2] 8a 03 [2] a4 21 [2] b0 3a [2] bf 20 [2] a1 3d [2] a3 3c [2] b8 3a [2] a4 3d [2] b8 12 }

  condition:
    any of them
}
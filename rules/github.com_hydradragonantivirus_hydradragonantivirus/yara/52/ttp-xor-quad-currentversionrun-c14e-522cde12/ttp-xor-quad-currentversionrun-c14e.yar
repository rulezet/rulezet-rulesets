rule TTP_XOR_QUAD_CurrentVersionRun_c14e {
  strings:
    $key_c14e = { 92 21 [2] b6 2f [2] 9d 03 [2] b3 21 [2] a7 3a [2] a8 20 [2] b6 3d [2] b4 3c [2] af 3a [2] b3 3d [2] af 12 }

  condition:
    any of them
}
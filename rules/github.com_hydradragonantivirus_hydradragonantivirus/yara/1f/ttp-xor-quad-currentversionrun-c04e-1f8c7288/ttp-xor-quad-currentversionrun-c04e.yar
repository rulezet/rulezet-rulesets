rule TTP_XOR_QUAD_CurrentVersionRun_c04e {
  strings:
    $key_c04e = { 93 21 [2] b7 2f [2] 9c 03 [2] b2 21 [2] a6 3a [2] a9 20 [2] b7 3d [2] b5 3c [2] ae 3a [2] b2 3d [2] ae 12 }

  condition:
    any of them
}
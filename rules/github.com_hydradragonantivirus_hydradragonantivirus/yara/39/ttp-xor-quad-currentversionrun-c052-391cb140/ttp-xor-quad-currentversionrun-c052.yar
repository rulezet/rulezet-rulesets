rule TTP_XOR_QUAD_CurrentVersionRun_c052 {
  strings:
    $key_c052 = { 93 3d [2] b7 33 [2] 9c 1f [2] b2 3d [2] a6 26 [2] a9 3c [2] b7 21 [2] b5 20 [2] ae 26 [2] b2 21 [2] ae 0e }

  condition:
    any of them
}
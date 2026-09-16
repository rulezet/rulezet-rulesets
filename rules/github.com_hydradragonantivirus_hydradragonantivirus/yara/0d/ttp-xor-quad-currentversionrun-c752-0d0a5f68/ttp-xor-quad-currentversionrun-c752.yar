rule TTP_XOR_QUAD_CurrentVersionRun_c752 {
  strings:
    $key_c752 = { 94 3d [2] b0 33 [2] 9b 1f [2] b5 3d [2] a1 26 [2] ae 3c [2] b0 21 [2] b2 20 [2] a9 26 [2] b5 21 [2] a9 0e }

  condition:
    any of them
}
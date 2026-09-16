rule TTP_XOR_QUAD_CurrentVersionRun_e45c {
  strings:
    $key_e45c = { b7 33 [2] 93 3d [2] b8 11 [2] 96 33 [2] 82 28 [2] 8d 32 [2] 93 2f [2] 91 2e [2] 8a 28 [2] 96 2f [2] 8a 00 }

  condition:
    any of them
}
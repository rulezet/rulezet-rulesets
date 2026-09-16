rule TTP_XOR_QUAD_CurrentVersionRun_235c {
  strings:
    $key_235c = { 70 33 [2] 54 3d [2] 7f 11 [2] 51 33 [2] 45 28 [2] 4a 32 [2] 54 2f [2] 56 2e [2] 4d 28 [2] 51 2f [2] 4d 00 }

  condition:
    any of them
}
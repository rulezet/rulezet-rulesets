rule TTP_XOR_QUAD_CurrentVersionRun_445c {
  strings:
    $key_445c = { 17 33 [2] 33 3d [2] 18 11 [2] 36 33 [2] 22 28 [2] 2d 32 [2] 33 2f [2] 31 2e [2] 2a 28 [2] 36 2f [2] 2a 00 }

  condition:
    any of them
}
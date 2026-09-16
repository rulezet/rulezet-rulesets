rule TTP_XOR_QUAD_CurrentVersionRun_185c {
  strings:
    $key_185c = { 4b 33 [2] 6f 3d [2] 44 11 [2] 6a 33 [2] 7e 28 [2] 71 32 [2] 6f 2f [2] 6d 2e [2] 76 28 [2] 6a 2f [2] 76 00 }

  condition:
    any of them
}
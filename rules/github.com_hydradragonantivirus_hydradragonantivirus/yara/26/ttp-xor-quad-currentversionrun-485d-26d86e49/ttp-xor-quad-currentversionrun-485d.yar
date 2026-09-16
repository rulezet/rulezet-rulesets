rule TTP_XOR_QUAD_CurrentVersionRun_485d {
  strings:
    $key_485d = { 1b 32 [2] 3f 3c [2] 14 10 [2] 3a 32 [2] 2e 29 [2] 21 33 [2] 3f 2e [2] 3d 2f [2] 26 29 [2] 3a 2e [2] 26 01 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_3e5c {
  strings:
    $key_3e5c = { 6d 33 [2] 49 3d [2] 62 11 [2] 4c 33 [2] 58 28 [2] 57 32 [2] 49 2f [2] 4b 2e [2] 50 28 [2] 4c 2f [2] 50 00 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0e5c {
  strings:
    $key_0e5c = { 5d 33 [2] 79 3d [2] 52 11 [2] 7c 33 [2] 68 28 [2] 67 32 [2] 79 2f [2] 7b 2e [2] 60 28 [2] 7c 2f [2] 60 00 }

  condition:
    any of them
}
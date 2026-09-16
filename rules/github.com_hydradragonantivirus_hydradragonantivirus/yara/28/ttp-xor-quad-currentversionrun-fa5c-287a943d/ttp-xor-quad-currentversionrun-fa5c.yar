rule TTP_XOR_QUAD_CurrentVersionRun_fa5c {
  strings:
    $key_fa5c = { a9 33 [2] 8d 3d [2] a6 11 [2] 88 33 [2] 9c 28 [2] 93 32 [2] 8d 2f [2] 8f 2e [2] 94 28 [2] 88 2f [2] 94 00 }

  condition:
    any of them
}
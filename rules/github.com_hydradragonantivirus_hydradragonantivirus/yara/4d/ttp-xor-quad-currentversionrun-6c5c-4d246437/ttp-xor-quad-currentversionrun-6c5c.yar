rule TTP_XOR_QUAD_CurrentVersionRun_6c5c {
  strings:
    $key_6c5c = { 3f 33 [2] 1b 3d [2] 30 11 [2] 1e 33 [2] 0a 28 [2] 05 32 [2] 1b 2f [2] 19 2e [2] 02 28 [2] 1e 2f [2] 02 00 }

  condition:
    any of them
}
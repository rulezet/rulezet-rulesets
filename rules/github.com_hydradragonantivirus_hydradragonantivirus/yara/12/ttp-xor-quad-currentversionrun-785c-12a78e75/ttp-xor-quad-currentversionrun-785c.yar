rule TTP_XOR_QUAD_CurrentVersionRun_785c {
  strings:
    $key_785c = { 2b 33 [2] 0f 3d [2] 24 11 [2] 0a 33 [2] 1e 28 [2] 11 32 [2] 0f 2f [2] 0d 2e [2] 16 28 [2] 0a 2f [2] 16 00 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_315d {
  strings:
    $key_315d = { 62 32 [2] 46 3c [2] 6d 10 [2] 43 32 [2] 57 29 [2] 58 33 [2] 46 2e [2] 44 2f [2] 5f 29 [2] 43 2e [2] 5f 01 }

  condition:
    any of them
}
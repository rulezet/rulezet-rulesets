rule TTP_XOR_QUAD_CurrentVersionRun_255d {
  strings:
    $key_255d = { 76 32 [2] 52 3c [2] 79 10 [2] 57 32 [2] 43 29 [2] 4c 33 [2] 52 2e [2] 50 2f [2] 4b 29 [2] 57 2e [2] 4b 01 }

  condition:
    any of them
}
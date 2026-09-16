rule TTP_XOR_QUAD_CurrentVersionRun_2d5d {
  strings:
    $key_2d5d = { 7e 32 [2] 5a 3c [2] 71 10 [2] 5f 32 [2] 4b 29 [2] 44 33 [2] 5a 2e [2] 58 2f [2] 43 29 [2] 5f 2e [2] 43 01 }

  condition:
    any of them
}
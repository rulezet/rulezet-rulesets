rule TTP_XOR_QUAD_CurrentVersionRun_235d {
  strings:
    $key_235d = { 70 32 [2] 54 3c [2] 7f 10 [2] 51 32 [2] 45 29 [2] 4a 33 [2] 54 2e [2] 56 2f [2] 4d 29 [2] 51 2e [2] 4d 01 }

  condition:
    any of them
}
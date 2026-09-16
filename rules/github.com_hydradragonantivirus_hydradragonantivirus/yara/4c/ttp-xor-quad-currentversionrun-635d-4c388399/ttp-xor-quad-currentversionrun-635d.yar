rule TTP_XOR_QUAD_CurrentVersionRun_635d {
  strings:
    $key_635d = { 30 32 [2] 14 3c [2] 3f 10 [2] 11 32 [2] 05 29 [2] 0a 33 [2] 14 2e [2] 16 2f [2] 0d 29 [2] 11 2e [2] 0d 01 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_782c {
  strings:
    $key_782c = { 2b 43 [2] 0f 4d [2] 24 61 [2] 0a 43 [2] 1e 58 [2] 11 42 [2] 0f 5f [2] 0d 5e [2] 16 58 [2] 0a 5f [2] 16 70 }

  condition:
    any of them
}
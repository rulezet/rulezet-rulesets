rule TTP_XOR_QUAD_CurrentVersionRun_366d {
  strings:
    $key_366d = { 65 02 [2] 41 0c [2] 6a 20 [2] 44 02 [2] 50 19 [2] 5f 03 [2] 41 1e [2] 43 1f [2] 58 19 [2] 44 1e [2] 58 31 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_551b {
  strings:
    $key_551b = { 06 74 [2] 22 7a [2] 09 56 [2] 27 74 [2] 33 6f [2] 3c 75 [2] 22 68 [2] 20 69 [2] 3b 6f [2] 27 68 [2] 3b 47 }

  condition:
    any of them
}
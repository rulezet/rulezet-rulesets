rule TTP_XOR_QUAD_CurrentVersionRun_1e7b {
  strings:
    $key_1e7b = { 4d 14 [2] 69 1a [2] 42 36 [2] 6c 14 [2] 78 0f [2] 77 15 [2] 69 08 [2] 6b 09 [2] 70 0f [2] 6c 08 [2] 70 27 }

  condition:
    any of them
}
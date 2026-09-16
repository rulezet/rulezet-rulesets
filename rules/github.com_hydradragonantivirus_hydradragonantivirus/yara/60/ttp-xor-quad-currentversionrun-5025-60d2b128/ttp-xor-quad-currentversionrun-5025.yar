rule TTP_XOR_QUAD_CurrentVersionRun_5025 {
  strings:
    $key_5025 = { 03 4a [2] 27 44 [2] 0c 68 [2] 22 4a [2] 36 51 [2] 39 4b [2] 27 56 [2] 25 57 [2] 3e 51 [2] 22 56 [2] 3e 79 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_1e39 {
  strings:
    $key_1e39 = { 4d 56 [2] 69 58 [2] 42 74 [2] 6c 56 [2] 78 4d [2] 77 57 [2] 69 4a [2] 6b 4b [2] 70 4d [2] 6c 4a [2] 70 65 }

  condition:
    any of them
}
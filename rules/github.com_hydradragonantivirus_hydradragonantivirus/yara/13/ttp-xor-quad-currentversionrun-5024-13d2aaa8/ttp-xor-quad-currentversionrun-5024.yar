rule TTP_XOR_QUAD_CurrentVersionRun_5024 {
  strings:
    $key_5024 = { 03 4b [2] 27 45 [2] 0c 69 [2] 22 4b [2] 36 50 [2] 39 4a [2] 27 57 [2] 25 56 [2] 3e 50 [2] 22 57 [2] 3e 78 }

  condition:
    any of them
}
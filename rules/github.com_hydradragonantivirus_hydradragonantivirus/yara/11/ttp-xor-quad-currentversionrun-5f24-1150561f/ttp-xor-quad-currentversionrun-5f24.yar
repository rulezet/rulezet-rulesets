rule TTP_XOR_QUAD_CurrentVersionRun_5f24 {
  strings:
    $key_5f24 = { 0c 4b [2] 28 45 [2] 03 69 [2] 2d 4b [2] 39 50 [2] 36 4a [2] 28 57 [2] 2a 56 [2] 31 50 [2] 2d 57 [2] 31 78 }

  condition:
    any of them
}
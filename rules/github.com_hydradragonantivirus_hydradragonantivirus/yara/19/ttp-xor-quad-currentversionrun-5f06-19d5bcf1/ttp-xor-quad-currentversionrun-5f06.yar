rule TTP_XOR_QUAD_CurrentVersionRun_5f06 {
  strings:
    $key_5f06 = { 0c 69 [2] 28 67 [2] 03 4b [2] 2d 69 [2] 39 72 [2] 36 68 [2] 28 75 [2] 2a 74 [2] 31 72 [2] 2d 75 [2] 31 5a }

  condition:
    any of them
}
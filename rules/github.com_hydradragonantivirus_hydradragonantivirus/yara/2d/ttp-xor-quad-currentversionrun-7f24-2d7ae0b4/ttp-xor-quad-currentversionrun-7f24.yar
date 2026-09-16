rule TTP_XOR_QUAD_CurrentVersionRun_7f24 {
  strings:
    $key_7f24 = { 2c 4b [2] 08 45 [2] 23 69 [2] 0d 4b [2] 19 50 [2] 16 4a [2] 08 57 [2] 0a 56 [2] 11 50 [2] 0d 57 [2] 11 78 }

  condition:
    any of them
}
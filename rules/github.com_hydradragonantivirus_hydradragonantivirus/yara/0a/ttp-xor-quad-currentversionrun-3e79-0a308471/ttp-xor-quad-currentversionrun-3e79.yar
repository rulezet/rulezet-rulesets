rule TTP_XOR_QUAD_CurrentVersionRun_3e79 {
  strings:
    $key_3e79 = { 6d 16 [2] 49 18 [2] 62 34 [2] 4c 16 [2] 58 0d [2] 57 17 [2] 49 0a [2] 4b 0b [2] 50 0d [2] 4c 0a [2] 50 25 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0f79 {
  strings:
    $key_0f79 = { 5c 16 [2] 78 18 [2] 53 34 [2] 7d 16 [2] 69 0d [2] 66 17 [2] 78 0a [2] 7a 0b [2] 61 0d [2] 7d 0a [2] 61 25 }

  condition:
    any of them
}
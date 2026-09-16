rule TTP_XOR_QUAD_CurrentVersionRun_0f78 {
  strings:
    $key_0f78 = { 5c 17 [2] 78 19 [2] 53 35 [2] 7d 17 [2] 69 0c [2] 66 16 [2] 78 0b [2] 7a 0a [2] 61 0c [2] 7d 0b [2] 61 24 }

  condition:
    any of them
}
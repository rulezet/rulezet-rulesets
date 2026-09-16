rule TTP_XOR_QUAD_CurrentVersionRun_0f54 {
  strings:
    $key_0f54 = { 5c 3b [2] 78 35 [2] 53 19 [2] 7d 3b [2] 69 20 [2] 66 3a [2] 78 27 [2] 7a 26 [2] 61 20 [2] 7d 27 [2] 61 08 }

  condition:
    any of them
}
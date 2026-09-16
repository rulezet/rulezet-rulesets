rule TTP_XOR_QUAD_CurrentVersionRun_7854 {
  strings:
    $key_7854 = { 2b 3b [2] 0f 35 [2] 24 19 [2] 0a 3b [2] 1e 20 [2] 11 3a [2] 0f 27 [2] 0d 26 [2] 16 20 [2] 0a 27 [2] 16 08 }

  condition:
    any of them
}
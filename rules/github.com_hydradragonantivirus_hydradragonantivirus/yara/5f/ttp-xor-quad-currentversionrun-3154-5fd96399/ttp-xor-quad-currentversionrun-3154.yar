rule TTP_XOR_QUAD_CurrentVersionRun_3154 {
  strings:
    $key_3154 = { 62 3b [2] 46 35 [2] 6d 19 [2] 43 3b [2] 57 20 [2] 58 3a [2] 46 27 [2] 44 26 [2] 5f 20 [2] 43 27 [2] 5f 08 }

  condition:
    any of them
}
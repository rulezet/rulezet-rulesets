rule TTP_XOR_QUAD_CurrentVersionRun_3125 {
  strings:
    $key_3125 = { 62 4a [2] 46 44 [2] 6d 68 [2] 43 4a [2] 57 51 [2] 58 4b [2] 46 56 [2] 44 57 [2] 5f 51 [2] 43 56 [2] 5f 79 }

  condition:
    any of them
}
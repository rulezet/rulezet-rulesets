rule TTP_XOR_QUAD_CurrentVersionRun_3138 {
  strings:
    $key_3138 = { 62 57 [2] 46 59 [2] 6d 75 [2] 43 57 [2] 57 4c [2] 58 56 [2] 46 4b [2] 44 4a [2] 5f 4c [2] 43 4b [2] 5f 64 }

  condition:
    any of them
}
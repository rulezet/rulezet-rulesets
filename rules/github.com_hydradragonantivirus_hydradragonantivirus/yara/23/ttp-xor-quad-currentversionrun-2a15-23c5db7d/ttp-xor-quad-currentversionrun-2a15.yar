rule TTP_XOR_QUAD_CurrentVersionRun_2a15 {
  strings:
    $key_2a15 = { 79 7a [2] 5d 74 [2] 76 58 [2] 58 7a [2] 4c 61 [2] 43 7b [2] 5d 66 [2] 5f 67 [2] 44 61 [2] 58 66 [2] 44 49 }

  condition:
    any of them
}
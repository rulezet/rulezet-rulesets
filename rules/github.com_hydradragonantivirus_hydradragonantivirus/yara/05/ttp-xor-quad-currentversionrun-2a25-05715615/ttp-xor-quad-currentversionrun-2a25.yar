rule TTP_XOR_QUAD_CurrentVersionRun_2a25 {
  strings:
    $key_2a25 = { 79 4a [2] 5d 44 [2] 76 68 [2] 58 4a [2] 4c 51 [2] 43 4b [2] 5d 56 [2] 5f 57 [2] 44 51 [2] 58 56 [2] 44 79 }

  condition:
    any of them
}
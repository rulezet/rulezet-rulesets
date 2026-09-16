rule TTP_XOR_QUAD_CurrentVersionRun_3e25 {
  strings:
    $key_3e25 = { 6d 4a [2] 49 44 [2] 62 68 [2] 4c 4a [2] 58 51 [2] 57 4b [2] 49 56 [2] 4b 57 [2] 50 51 [2] 4c 56 [2] 50 79 }

  condition:
    any of them
}
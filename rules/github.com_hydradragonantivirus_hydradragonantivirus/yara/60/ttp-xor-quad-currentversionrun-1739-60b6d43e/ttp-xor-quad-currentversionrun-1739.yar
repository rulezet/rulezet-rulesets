rule TTP_XOR_QUAD_CurrentVersionRun_1739 {
  strings:
    $key_1739 = { 44 56 [2] 60 58 [2] 4b 74 [2] 65 56 [2] 71 4d [2] 7e 57 [2] 60 4a [2] 62 4b [2] 79 4d [2] 65 4a [2] 79 65 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_1f08 {
  strings:
    $key_1f08 = { 4c 67 [2] 68 69 [2] 43 45 [2] 6d 67 [2] 79 7c [2] 76 66 [2] 68 7b [2] 6a 7a [2] 71 7c [2] 6d 7b [2] 71 54 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_1f14 {
  strings:
    $key_1f14 = { 4c 7b [2] 68 75 [2] 43 59 [2] 6d 7b [2] 79 60 [2] 76 7a [2] 68 67 [2] 6a 66 [2] 71 60 [2] 6d 67 [2] 71 48 }

  condition:
    any of them
}
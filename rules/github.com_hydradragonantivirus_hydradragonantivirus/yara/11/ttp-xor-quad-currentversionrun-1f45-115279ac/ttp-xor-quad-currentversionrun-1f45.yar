rule TTP_XOR_QUAD_CurrentVersionRun_1f45 {
  strings:
    $key_1f45 = { 4c 2a [2] 68 24 [2] 43 08 [2] 6d 2a [2] 79 31 [2] 76 2b [2] 68 36 [2] 6a 37 [2] 71 31 [2] 6d 36 [2] 71 19 }

  condition:
    any of them
}
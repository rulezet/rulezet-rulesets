rule TTP_XOR_QUAD_CurrentVersionRun_2a05 {
  strings:
    $key_2a05 = { 79 6a [2] 5d 64 [2] 76 48 [2] 58 6a [2] 4c 71 [2] 43 6b [2] 5d 76 [2] 5f 77 [2] 44 71 [2] 58 76 [2] 44 59 }

  condition:
    any of them
}
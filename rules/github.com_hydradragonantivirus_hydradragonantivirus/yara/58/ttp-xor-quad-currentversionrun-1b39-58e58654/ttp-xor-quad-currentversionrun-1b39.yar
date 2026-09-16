rule TTP_XOR_QUAD_CurrentVersionRun_1b39 {
  strings:
    $key_1b39 = { 48 56 [2] 6c 58 [2] 47 74 [2] 69 56 [2] 7d 4d [2] 72 57 [2] 6c 4a [2] 6e 4b [2] 75 4d [2] 69 4a [2] 75 65 }

  condition:
    any of them
}
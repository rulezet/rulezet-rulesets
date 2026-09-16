rule TTP_XOR_QUAD_CurrentVersionRun_4e39 {
  strings:
    $key_4e39 = { 1d 56 [2] 39 58 [2] 12 74 [2] 3c 56 [2] 28 4d [2] 27 57 [2] 39 4a [2] 3b 4b [2] 20 4d [2] 3c 4a [2] 20 65 }

  condition:
    any of them
}
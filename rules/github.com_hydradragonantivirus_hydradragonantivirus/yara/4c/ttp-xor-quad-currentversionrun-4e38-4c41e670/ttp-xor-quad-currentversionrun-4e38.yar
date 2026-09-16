rule TTP_XOR_QUAD_CurrentVersionRun_4e38 {
  strings:
    $key_4e38 = { 1d 57 [2] 39 59 [2] 12 75 [2] 3c 57 [2] 28 4c [2] 27 56 [2] 39 4b [2] 3b 4a [2] 20 4c [2] 3c 4b [2] 20 64 }

  condition:
    any of them
}
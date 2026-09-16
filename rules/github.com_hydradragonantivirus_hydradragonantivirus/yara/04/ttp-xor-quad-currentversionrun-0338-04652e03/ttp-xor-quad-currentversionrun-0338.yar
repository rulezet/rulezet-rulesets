rule TTP_XOR_QUAD_CurrentVersionRun_0338 {
  strings:
    $key_0338 = { 50 57 [2] 74 59 [2] 5f 75 [2] 71 57 [2] 65 4c [2] 6a 56 [2] 74 4b [2] 76 4a [2] 6d 4c [2] 71 4b [2] 6d 64 }

  condition:
    any of them
}
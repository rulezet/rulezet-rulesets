rule TTP_XOR_QUAD_CurrentVersionRun_6338 {
  strings:
    $key_6338 = { 30 57 [2] 14 59 [2] 3f 75 [2] 11 57 [2] 05 4c [2] 0a 56 [2] 14 4b [2] 16 4a [2] 0d 4c [2] 11 4b [2] 0d 64 }

  condition:
    any of them
}
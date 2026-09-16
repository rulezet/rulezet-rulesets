rule TTP_XOR_QUAD_CurrentVersionRun_0438 {
  strings:
    $key_0438 = { 57 57 [2] 73 59 [2] 58 75 [2] 76 57 [2] 62 4c [2] 6d 56 [2] 73 4b [2] 71 4a [2] 6a 4c [2] 76 4b [2] 6a 64 }

  condition:
    any of them
}
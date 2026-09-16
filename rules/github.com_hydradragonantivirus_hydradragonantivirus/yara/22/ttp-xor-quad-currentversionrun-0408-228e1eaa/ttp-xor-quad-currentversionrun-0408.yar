rule TTP_XOR_QUAD_CurrentVersionRun_0408 {
  strings:
    $key_0408 = { 57 67 [2] 73 69 [2] 58 45 [2] 76 67 [2] 62 7c [2] 6d 66 [2] 73 7b [2] 71 7a [2] 6a 7c [2] 76 7b [2] 6a 54 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_042b {
  strings:
    $key_042b = { 57 44 [2] 73 4a [2] 58 66 [2] 76 44 [2] 62 5f [2] 6d 45 [2] 73 58 [2] 71 59 [2] 6a 5f [2] 76 58 [2] 6a 77 }

  condition:
    any of them
}
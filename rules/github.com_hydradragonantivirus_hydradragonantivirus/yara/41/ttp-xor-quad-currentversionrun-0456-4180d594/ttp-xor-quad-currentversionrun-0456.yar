rule TTP_XOR_QUAD_CurrentVersionRun_0456 {
  strings:
    $key_0456 = { 57 39 [2] 73 37 [2] 58 1b [2] 76 39 [2] 62 22 [2] 6d 38 [2] 73 25 [2] 71 24 [2] 6a 22 [2] 76 25 [2] 6a 0a }

  condition:
    any of them
}
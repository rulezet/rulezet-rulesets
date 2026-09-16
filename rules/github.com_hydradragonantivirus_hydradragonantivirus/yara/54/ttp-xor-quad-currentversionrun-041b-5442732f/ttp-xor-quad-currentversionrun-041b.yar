rule TTP_XOR_QUAD_CurrentVersionRun_041b {
  strings:
    $key_041b = { 57 74 [2] 73 7a [2] 58 56 [2] 76 74 [2] 62 6f [2] 6d 75 [2] 73 68 [2] 71 69 [2] 6a 6f [2] 76 68 [2] 6a 47 }

  condition:
    any of them
}
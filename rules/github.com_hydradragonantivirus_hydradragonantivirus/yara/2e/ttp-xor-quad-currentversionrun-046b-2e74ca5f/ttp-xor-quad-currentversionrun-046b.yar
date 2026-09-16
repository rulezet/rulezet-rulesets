rule TTP_XOR_QUAD_CurrentVersionRun_046b {
  strings:
    $key_046b = { 57 04 [2] 73 0a [2] 58 26 [2] 76 04 [2] 62 1f [2] 6d 05 [2] 73 18 [2] 71 19 [2] 6a 1f [2] 76 18 [2] 6a 37 }

  condition:
    any of them
}
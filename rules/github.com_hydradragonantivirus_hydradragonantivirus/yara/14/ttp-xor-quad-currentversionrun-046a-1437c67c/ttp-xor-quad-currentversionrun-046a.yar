rule TTP_XOR_QUAD_CurrentVersionRun_046a {
  strings:
    $key_046a = { 57 05 [2] 73 0b [2] 58 27 [2] 76 05 [2] 62 1e [2] 6d 04 [2] 73 19 [2] 71 18 [2] 6a 1e [2] 76 19 [2] 6a 36 }

  condition:
    any of them
}
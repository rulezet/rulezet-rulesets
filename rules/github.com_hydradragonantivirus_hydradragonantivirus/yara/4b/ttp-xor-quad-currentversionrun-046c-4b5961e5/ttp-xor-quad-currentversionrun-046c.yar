rule TTP_XOR_QUAD_CurrentVersionRun_046c {
  strings:
    $key_046c = { 57 03 [2] 73 0d [2] 58 21 [2] 76 03 [2] 62 18 [2] 6d 02 [2] 73 1f [2] 71 1e [2] 6a 18 [2] 76 1f [2] 6a 30 }

  condition:
    any of them
}
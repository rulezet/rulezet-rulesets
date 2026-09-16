rule TTP_XOR_QUAD_CurrentVersionRun_043c {
  strings:
    $key_043c = { 57 53 [2] 73 5d [2] 58 71 [2] 76 53 [2] 62 48 [2] 6d 52 [2] 73 4f [2] 71 4e [2] 6a 48 [2] 76 4f [2] 6a 60 }

  condition:
    any of them
}
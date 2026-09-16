rule TTP_XOR_QUAD_CurrentVersionRun_043a {
  strings:
    $key_043a = { 57 55 [2] 73 5b [2] 58 77 [2] 76 55 [2] 62 4e [2] 6d 54 [2] 73 49 [2] 71 48 [2] 6a 4e [2] 76 49 [2] 6a 66 }

  condition:
    any of them
}
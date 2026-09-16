rule TTP_XOR_QUAD_CurrentVersionRun_642d {
  strings:
    $key_642d = { 37 42 [2] 13 4c [2] 38 60 [2] 16 42 [2] 02 59 [2] 0d 43 [2] 13 5e [2] 11 5f [2] 0a 59 [2] 16 5e [2] 0a 71 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0401 {
  strings:
    $key_0401 = { 57 6e [2] 73 60 [2] 58 4c [2] 76 6e [2] 62 75 [2] 6d 6f [2] 73 72 [2] 71 73 [2] 6a 75 [2] 76 72 [2] 6a 5d }

  condition:
    any of them
}
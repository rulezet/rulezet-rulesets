rule TTP_XOR_QUAD_CurrentVersionRun_04ec {
  strings:
    $key_04ec = { 57 83 [2] 73 8d [2] 58 a1 [2] 76 83 [2] 62 98 [2] 6d 82 [2] 73 9f [2] 71 9e [2] 6a 98 [2] 76 9f [2] 6a b0 }

  condition:
    any of them
}
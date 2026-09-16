rule TTP_XOR_QUAD_CurrentVersionRun_49cf {
  strings:
    $key_49cf = { 1a a0 [2] 3e ae [2] 15 82 [2] 3b a0 [2] 2f bb [2] 20 a1 [2] 3e bc [2] 3c bd [2] 27 bb [2] 3b bc [2] 27 93 }

  condition:
    any of them
}
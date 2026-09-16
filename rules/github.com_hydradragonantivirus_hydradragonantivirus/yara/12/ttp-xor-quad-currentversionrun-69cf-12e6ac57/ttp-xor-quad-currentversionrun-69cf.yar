rule TTP_XOR_QUAD_CurrentVersionRun_69cf {
  strings:
    $key_69cf = { 3a a0 [2] 1e ae [2] 35 82 [2] 1b a0 [2] 0f bb [2] 00 a1 [2] 1e bc [2] 1c bd [2] 07 bb [2] 1b bc [2] 07 93 }

  condition:
    any of them
}
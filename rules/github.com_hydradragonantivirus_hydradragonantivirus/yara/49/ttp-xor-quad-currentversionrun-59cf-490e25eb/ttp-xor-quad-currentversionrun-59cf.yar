rule TTP_XOR_QUAD_CurrentVersionRun_59cf {
  strings:
    $key_59cf = { 0a a0 [2] 2e ae [2] 05 82 [2] 2b a0 [2] 3f bb [2] 30 a1 [2] 2e bc [2] 2c bd [2] 37 bb [2] 2b bc [2] 37 93 }

  condition:
    any of them
}
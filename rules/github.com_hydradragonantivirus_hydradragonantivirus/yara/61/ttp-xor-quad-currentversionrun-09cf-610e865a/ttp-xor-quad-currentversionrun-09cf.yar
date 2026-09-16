rule TTP_XOR_QUAD_CurrentVersionRun_09cf {
  strings:
    $key_09cf = { 5a a0 [2] 7e ae [2] 55 82 [2] 7b a0 [2] 6f bb [2] 60 a1 [2] 7e bc [2] 7c bd [2] 67 bb [2] 7b bc [2] 67 93 }

  condition:
    any of them
}
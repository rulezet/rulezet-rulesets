rule TTP_XOR_QUAD_CurrentVersionRun_3298 {
  strings:
    $key_3298 = { 61 f7 [2] 45 f9 [2] 6e d5 [2] 40 f7 [2] 54 ec [2] 5b f6 [2] 45 eb [2] 47 ea [2] 5c ec [2] 40 eb [2] 5c c4 }

  condition:
    any of them
}
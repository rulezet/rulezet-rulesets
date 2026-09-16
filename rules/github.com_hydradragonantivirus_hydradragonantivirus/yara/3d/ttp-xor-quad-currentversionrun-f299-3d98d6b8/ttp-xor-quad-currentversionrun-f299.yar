rule TTP_XOR_QUAD_CurrentVersionRun_f299 {
  strings:
    $key_f299 = { a1 f6 [2] 85 f8 [2] ae d4 [2] 80 f6 [2] 94 ed [2] 9b f7 [2] 85 ea [2] 87 eb [2] 9c ed [2] 80 ea [2] 9c c5 }

  condition:
    any of them
}
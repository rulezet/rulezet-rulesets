rule TTP_XOR_QUAD_CurrentVersionRun_3299 {
  strings:
    $key_3299 = { 61 f6 [2] 45 f8 [2] 6e d4 [2] 40 f6 [2] 54 ed [2] 5b f7 [2] 45 ea [2] 47 eb [2] 5c ed [2] 40 ea [2] 5c c5 }

  condition:
    any of them
}
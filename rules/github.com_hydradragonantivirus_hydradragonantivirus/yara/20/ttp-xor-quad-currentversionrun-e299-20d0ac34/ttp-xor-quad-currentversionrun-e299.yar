rule TTP_XOR_QUAD_CurrentVersionRun_e299 {
  strings:
    $key_e299 = { b1 f6 [2] 95 f8 [2] be d4 [2] 90 f6 [2] 84 ed [2] 8b f7 [2] 95 ea [2] 97 eb [2] 8c ed [2] 90 ea [2] 8c c5 }

  condition:
    any of them
}
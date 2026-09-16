rule TTP_XOR_QUAD_CurrentVersionRun_e284 {
  strings:
    $key_e284 = { b1 eb [2] 95 e5 [2] be c9 [2] 90 eb [2] 84 f0 [2] 8b ea [2] 95 f7 [2] 97 f6 [2] 8c f0 [2] 90 f7 [2] 8c d8 }

  condition:
    any of them
}
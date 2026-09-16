rule TTP_XOR_QUAD_CurrentVersionRun_e498 {
  strings:
    $key_e498 = { b7 f7 [2] 93 f9 [2] b8 d5 [2] 96 f7 [2] 82 ec [2] 8d f6 [2] 93 eb [2] 91 ea [2] 8a ec [2] 96 eb [2] 8a c4 }

  condition:
    any of them
}
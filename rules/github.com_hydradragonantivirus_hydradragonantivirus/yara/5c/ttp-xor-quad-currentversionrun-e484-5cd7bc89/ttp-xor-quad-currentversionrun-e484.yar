rule TTP_XOR_QUAD_CurrentVersionRun_e484 {
  strings:
    $key_e484 = { b7 eb [2] 93 e5 [2] b8 c9 [2] 96 eb [2] 82 f0 [2] 8d ea [2] 93 f7 [2] 91 f6 [2] 8a f0 [2] 96 f7 [2] 8a d8 }

  condition:
    any of them
}
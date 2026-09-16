rule TTP_XOR_QUAD_CurrentVersionRun_e685 {
  strings:
    $key_e685 = { b5 ea [2] 91 e4 [2] ba c8 [2] 94 ea [2] 80 f1 [2] 8f eb [2] 91 f6 [2] 93 f7 [2] 88 f1 [2] 94 f6 [2] 88 d9 }

  condition:
    any of them
}
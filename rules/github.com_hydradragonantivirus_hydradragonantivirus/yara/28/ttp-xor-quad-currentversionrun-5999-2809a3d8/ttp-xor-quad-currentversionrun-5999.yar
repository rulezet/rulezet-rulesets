rule TTP_XOR_QUAD_CurrentVersionRun_5999 {
  strings:
    $key_5999 = { 0a f6 [2] 2e f8 [2] 05 d4 [2] 2b f6 [2] 3f ed [2] 30 f7 [2] 2e ea [2] 2c eb [2] 37 ed [2] 2b ea [2] 37 c5 }

  condition:
    any of them
}
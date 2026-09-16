rule TTP_XOR_QUAD_CurrentVersionRun_4999 {
  strings:
    $key_4999 = { 1a f6 [2] 3e f8 [2] 15 d4 [2] 3b f6 [2] 2f ed [2] 20 f7 [2] 3e ea [2] 3c eb [2] 27 ed [2] 3b ea [2] 27 c5 }

  condition:
    any of them
}
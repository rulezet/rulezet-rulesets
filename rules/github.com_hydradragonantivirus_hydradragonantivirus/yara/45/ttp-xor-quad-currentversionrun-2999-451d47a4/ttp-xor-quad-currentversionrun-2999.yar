rule TTP_XOR_QUAD_CurrentVersionRun_2999 {
  strings:
    $key_2999 = { 7a f6 [2] 5e f8 [2] 75 d4 [2] 5b f6 [2] 4f ed [2] 40 f7 [2] 5e ea [2] 5c eb [2] 47 ed [2] 5b ea [2] 47 c5 }

  condition:
    any of them
}
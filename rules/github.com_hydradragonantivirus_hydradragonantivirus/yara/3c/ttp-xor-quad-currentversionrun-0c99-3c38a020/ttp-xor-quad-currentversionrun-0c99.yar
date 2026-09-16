rule TTP_XOR_QUAD_CurrentVersionRun_0c99 {
  strings:
    $key_0c99 = { 5f f6 [2] 7b f8 [2] 50 d4 [2] 7e f6 [2] 6a ed [2] 65 f7 [2] 7b ea [2] 79 eb [2] 62 ed [2] 7e ea [2] 62 c5 }

  condition:
    any of them
}
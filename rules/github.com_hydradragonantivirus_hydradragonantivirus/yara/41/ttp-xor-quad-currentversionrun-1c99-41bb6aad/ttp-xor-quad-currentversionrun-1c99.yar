rule TTP_XOR_QUAD_CurrentVersionRun_1c99 {
  strings:
    $key_1c99 = { 4f f6 [2] 6b f8 [2] 40 d4 [2] 6e f6 [2] 7a ed [2] 75 f7 [2] 6b ea [2] 69 eb [2] 72 ed [2] 6e ea [2] 72 c5 }

  condition:
    any of them
}
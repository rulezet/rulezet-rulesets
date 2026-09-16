rule TTP_XOR_QUAD_CurrentVersionRun_2c99 {
  strings:
    $key_2c99 = { 7f f6 [2] 5b f8 [2] 70 d4 [2] 5e f6 [2] 4a ed [2] 45 f7 [2] 5b ea [2] 59 eb [2] 42 ed [2] 5e ea [2] 42 c5 }

  condition:
    any of them
}
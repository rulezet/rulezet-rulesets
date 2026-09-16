rule TTP_XOR_QUAD_CurrentVersionRun_1d99 {
  strings:
    $key_1d99 = { 4e f6 [2] 6a f8 [2] 41 d4 [2] 6f f6 [2] 7b ed [2] 74 f7 [2] 6a ea [2] 68 eb [2] 73 ed [2] 6f ea [2] 73 c5 }

  condition:
    any of them
}
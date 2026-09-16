rule TTP_XOR_QUAD_CurrentVersionRun_0d99 {
  strings:
    $key_0d99 = { 5e f6 [2] 7a f8 [2] 51 d4 [2] 7f f6 [2] 6b ed [2] 64 f7 [2] 7a ea [2] 78 eb [2] 63 ed [2] 7f ea [2] 63 c5 }

  condition:
    any of them
}
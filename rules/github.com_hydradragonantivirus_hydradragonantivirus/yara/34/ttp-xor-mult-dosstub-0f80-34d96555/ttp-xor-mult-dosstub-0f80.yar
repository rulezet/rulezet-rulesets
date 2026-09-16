rule TTP_XOR_MULT_DOSStub_0f80 {
  strings:
    $key_0f80 = { 5b e8 [2] 2f f0 [2] 68 f2 [2] 2f e3 [2] 61 ef [2] 6d e5 [2] 7a ee [2] 61 a0 [2] 5c }

  condition:
    any of them
}
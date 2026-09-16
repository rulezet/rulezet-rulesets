rule TTP_XOR_MULT_DOSStub_3f80 {
  strings:
    $key_3f80 = { 6b e8 [2] 1f f0 [2] 58 f2 [2] 1f e3 [2] 51 ef [2] 5d e5 [2] 4a ee [2] 51 a0 [2] 6c }

  condition:
    any of them
}
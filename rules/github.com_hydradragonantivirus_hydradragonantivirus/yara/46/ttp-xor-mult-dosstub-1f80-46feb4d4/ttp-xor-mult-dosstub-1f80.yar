rule TTP_XOR_MULT_DOSStub_1f80 {
  strings:
    $key_1f80 = { 4b e8 [2] 3f f0 [2] 78 f2 [2] 3f e3 [2] 71 ef [2] 7d e5 [2] 6a ee [2] 71 a0 [2] 4c }

  condition:
    any of them
}
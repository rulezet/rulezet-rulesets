rule TTP_XOR_MULT_DOSStub_2f80 {
  strings:
    $key_2f80 = { 7b e8 [2] 0f f0 [2] 48 f2 [2] 0f e3 [2] 41 ef [2] 4d e5 [2] 5a ee [2] 41 a0 [2] 7c }

  condition:
    any of them
}
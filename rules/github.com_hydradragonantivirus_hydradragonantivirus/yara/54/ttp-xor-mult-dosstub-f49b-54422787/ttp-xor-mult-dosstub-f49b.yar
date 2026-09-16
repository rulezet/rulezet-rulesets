rule TTP_XOR_MULT_DOSStub_f49b {
  strings:
    $key_f49b = { a0 f3 [2] d4 eb [2] 93 e9 [2] d4 f8 [2] 9a f4 [2] 96 fe [2] 81 f5 [2] 9a bb [2] a7 }

  condition:
    any of them
}
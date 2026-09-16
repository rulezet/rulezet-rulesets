rule TTP_XOR_MULT_DOSStub_6f86 {
  strings:
    $key_6f86 = { 3b ee [2] 4f f6 [2] 08 f4 [2] 4f e5 [2] 01 e9 [2] 0d e3 [2] 1a e8 [2] 01 a6 [2] 3c }

  condition:
    any of them
}
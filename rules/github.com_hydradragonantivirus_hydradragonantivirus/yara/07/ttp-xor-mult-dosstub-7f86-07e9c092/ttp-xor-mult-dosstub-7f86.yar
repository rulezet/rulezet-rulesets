rule TTP_XOR_MULT_DOSStub_7f86 {
  strings:
    $key_7f86 = { 2b ee [2] 5f f6 [2] 18 f4 [2] 5f e5 [2] 11 e9 [2] 1d e3 [2] 0a e8 [2] 11 a6 [2] 2c }

  condition:
    any of them
}
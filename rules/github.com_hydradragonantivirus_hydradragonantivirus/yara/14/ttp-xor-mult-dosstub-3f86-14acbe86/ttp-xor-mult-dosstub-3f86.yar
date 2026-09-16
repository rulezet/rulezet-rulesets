rule TTP_XOR_MULT_DOSStub_3f86 {
  strings:
    $key_3f86 = { 6b ee [2] 1f f6 [2] 58 f4 [2] 1f e5 [2] 51 e9 [2] 5d e3 [2] 4a e8 [2] 51 a6 [2] 6c }

  condition:
    any of them
}
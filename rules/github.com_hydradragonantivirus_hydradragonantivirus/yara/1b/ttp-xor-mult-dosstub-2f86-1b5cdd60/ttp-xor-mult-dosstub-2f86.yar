rule TTP_XOR_MULT_DOSStub_2f86 {
  strings:
    $key_2f86 = { 7b ee [2] 0f f6 [2] 48 f4 [2] 0f e5 [2] 41 e9 [2] 4d e3 [2] 5a e8 [2] 41 a6 [2] 7c }

  condition:
    any of them
}
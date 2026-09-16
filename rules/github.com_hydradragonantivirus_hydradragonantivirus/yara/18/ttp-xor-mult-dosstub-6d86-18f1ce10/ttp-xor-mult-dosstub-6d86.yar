rule TTP_XOR_MULT_DOSStub_6d86 {
  strings:
    $key_6d86 = { 39 ee [2] 4d f6 [2] 0a f4 [2] 4d e5 [2] 03 e9 [2] 0f e3 [2] 18 e8 [2] 03 a6 [2] 3e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8a86 {
  strings:
    $key_8a86 = { de ee [2] aa f6 [2] ed f4 [2] aa e5 [2] e4 e9 [2] e8 e3 [2] ff e8 [2] e4 a6 [2] d9 }

  condition:
    any of them
}
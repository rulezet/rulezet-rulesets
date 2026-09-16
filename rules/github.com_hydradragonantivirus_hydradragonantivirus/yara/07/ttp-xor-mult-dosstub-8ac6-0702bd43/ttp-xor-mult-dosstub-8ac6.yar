rule TTP_XOR_MULT_DOSStub_8ac6 {
  strings:
    $key_8ac6 = { de ae [2] aa b6 [2] ed b4 [2] aa a5 [2] e4 a9 [2] e8 a3 [2] ff a8 [2] e4 e6 [2] d9 }

  condition:
    any of them
}
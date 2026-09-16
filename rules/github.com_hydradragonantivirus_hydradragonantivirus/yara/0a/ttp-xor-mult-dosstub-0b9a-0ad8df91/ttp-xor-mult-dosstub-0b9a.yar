rule TTP_XOR_MULT_DOSStub_0b9a {
  strings:
    $key_0b9a = { 5f f2 [2] 2b ea [2] 6c e8 [2] 2b f9 [2] 65 f5 [2] 69 ff [2] 7e f4 [2] 65 ba [2] 58 }

  condition:
    any of them
}
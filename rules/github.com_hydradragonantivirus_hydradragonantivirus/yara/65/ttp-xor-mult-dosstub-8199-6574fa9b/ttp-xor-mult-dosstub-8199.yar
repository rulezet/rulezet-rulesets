rule TTP_XOR_MULT_DOSStub_8199 {
  strings:
    $key_8199 = { d5 f1 [2] a1 e9 [2] e6 eb [2] a1 fa [2] ef f6 [2] e3 fc [2] f4 f7 [2] ef b9 [2] d2 }

  condition:
    any of them
}
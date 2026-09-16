rule TTP_XOR_MULT_DOSStub_8ad5 {
  strings:
    $key_8ad5 = { de bd [2] aa a5 [2] ed a7 [2] aa b6 [2] e4 ba [2] e8 b0 [2] ff bb [2] e4 f5 [2] d9 }

  condition:
    any of them
}
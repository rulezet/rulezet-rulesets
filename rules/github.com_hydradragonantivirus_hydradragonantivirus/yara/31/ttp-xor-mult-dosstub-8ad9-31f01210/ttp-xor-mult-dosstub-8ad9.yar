rule TTP_XOR_MULT_DOSStub_8ad9 {
  strings:
    $key_8ad9 = { de b1 [2] aa a9 [2] ed ab [2] aa ba [2] e4 b6 [2] e8 bc [2] ff b7 [2] e4 f9 [2] d9 }

  condition:
    any of them
}
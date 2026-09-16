rule TTP_XOR_MULT_DOSStub_8ad1 {
  strings:
    $key_8ad1 = { de b9 [2] aa a1 [2] ed a3 [2] aa b2 [2] e4 be [2] e8 b4 [2] ff bf [2] e4 f1 [2] d9 }

  condition:
    any of them
}
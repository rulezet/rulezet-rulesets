rule TTP_XOR_MULT_DOSStub_bcc7 {
  strings:
    $key_bcc7 = { e8 af [2] 9c b7 [2] db b5 [2] 9c a4 [2] d2 a8 [2] de a2 [2] c9 a9 [2] d2 e7 [2] ef }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bcc6 {
  strings:
    $key_bcc6 = { e8 ae [2] 9c b6 [2] db b4 [2] 9c a5 [2] d2 a9 [2] de a3 [2] c9 a8 [2] d2 e6 [2] ef }

  condition:
    any of them
}
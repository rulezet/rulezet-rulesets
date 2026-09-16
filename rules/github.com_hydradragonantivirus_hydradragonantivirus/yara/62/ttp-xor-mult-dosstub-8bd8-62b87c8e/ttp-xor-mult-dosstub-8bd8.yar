rule TTP_XOR_MULT_DOSStub_8bd8 {
  strings:
    $key_8bd8 = { df b0 [2] ab a8 [2] ec aa [2] ab bb [2] e5 b7 [2] e9 bd [2] fe b6 [2] e5 f8 [2] d8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0788 {
  strings:
    $key_0788 = { 53 e0 [2] 27 f8 [2] 60 fa [2] 27 eb [2] 69 e7 [2] 65 ed [2] 72 e6 [2] 69 a8 [2] 54 }

  condition:
    any of them
}
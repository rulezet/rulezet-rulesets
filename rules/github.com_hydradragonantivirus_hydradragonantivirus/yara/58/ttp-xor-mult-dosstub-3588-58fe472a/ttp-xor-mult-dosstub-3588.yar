rule TTP_XOR_MULT_DOSStub_3588 {
  strings:
    $key_3588 = { 61 e0 [2] 15 f8 [2] 52 fa [2] 15 eb [2] 5b e7 [2] 57 ed [2] 40 e6 [2] 5b a8 [2] 66 }

  condition:
    any of them
}
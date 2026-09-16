rule TTP_XOR_MULT_DOSStub_4588 {
  strings:
    $key_4588 = { 11 e0 [2] 65 f8 [2] 22 fa [2] 65 eb [2] 2b e7 [2] 27 ed [2] 30 e6 [2] 2b a8 [2] 16 }

  condition:
    any of them
}
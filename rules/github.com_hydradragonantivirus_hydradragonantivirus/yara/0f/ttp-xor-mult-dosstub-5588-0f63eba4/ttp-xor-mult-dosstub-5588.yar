rule TTP_XOR_MULT_DOSStub_5588 {
  strings:
    $key_5588 = { 01 e0 [2] 75 f8 [2] 32 fa [2] 75 eb [2] 3b e7 [2] 37 ed [2] 20 e6 [2] 3b a8 [2] 06 }

  condition:
    any of them
}
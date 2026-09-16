rule TTP_XOR_MULT_DOSStub_6088 {
  strings:
    $key_6088 = { 34 e0 [2] 40 f8 [2] 07 fa [2] 40 eb [2] 0e e7 [2] 02 ed [2] 15 e6 [2] 0e a8 [2] 33 }

  condition:
    any of them
}
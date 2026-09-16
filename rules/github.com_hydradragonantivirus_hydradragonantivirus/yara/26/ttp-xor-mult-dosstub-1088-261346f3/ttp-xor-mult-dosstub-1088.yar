rule TTP_XOR_MULT_DOSStub_1088 {
  strings:
    $key_1088 = { 44 e0 [2] 30 f8 [2] 77 fa [2] 30 eb [2] 7e e7 [2] 72 ed [2] 65 e6 [2] 7e a8 [2] 43 }

  condition:
    any of them
}
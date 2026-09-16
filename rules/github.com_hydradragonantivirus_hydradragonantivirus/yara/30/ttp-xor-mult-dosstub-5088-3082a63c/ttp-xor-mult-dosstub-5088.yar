rule TTP_XOR_MULT_DOSStub_5088 {
  strings:
    $key_5088 = { 04 e0 [2] 70 f8 [2] 37 fa [2] 70 eb [2] 3e e7 [2] 32 ed [2] 25 e6 [2] 3e a8 [2] 03 }

  condition:
    any of them
}
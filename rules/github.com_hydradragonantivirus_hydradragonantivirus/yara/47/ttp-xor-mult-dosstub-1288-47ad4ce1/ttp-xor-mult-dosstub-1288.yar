rule TTP_XOR_MULT_DOSStub_1288 {
  strings:
    $key_1288 = { 46 e0 [2] 32 f8 [2] 75 fa [2] 32 eb [2] 7c e7 [2] 70 ed [2] 67 e6 [2] 7c a8 [2] 41 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_d699 {
  strings:
    $key_d699 = { 82 f1 [2] f6 e9 [2] b1 eb [2] f6 fa [2] b8 f6 [2] b4 fc [2] a3 f7 [2] b8 b9 [2] 85 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8499 {
  strings:
    $key_8499 = { d0 f1 [2] a4 e9 [2] e3 eb [2] a4 fa [2] ea f6 [2] e6 fc [2] f1 f7 [2] ea b9 [2] d7 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_d099 {
  strings:
    $key_d099 = { 84 f1 [2] f0 e9 [2] b7 eb [2] f0 fa [2] be f6 [2] b2 fc [2] a5 f7 [2] be b9 [2] 83 }

  condition:
    any of them
}
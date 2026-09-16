rule TTP_XOR_MULT_DOSStub_c099 {
  strings:
    $key_c099 = { 94 f1 [2] e0 e9 [2] a7 eb [2] e0 fa [2] ae f6 [2] a2 fc [2] b5 f7 [2] ae b9 [2] 93 }

  condition:
    any of them
}
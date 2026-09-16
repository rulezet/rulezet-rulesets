rule TTP_XOR_MULT_DOSStub_e194 {
  strings:
    $key_e194 = { b5 fc [2] c1 e4 [2] 86 e6 [2] c1 f7 [2] 8f fb [2] 83 f1 [2] 94 fa [2] 8f b4 [2] b2 }

  condition:
    any of them
}
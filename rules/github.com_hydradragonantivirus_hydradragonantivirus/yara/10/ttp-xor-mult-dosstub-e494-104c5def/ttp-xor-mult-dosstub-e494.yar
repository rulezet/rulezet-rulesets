rule TTP_XOR_MULT_DOSStub_e494 {
  strings:
    $key_e494 = { b0 fc [2] c4 e4 [2] 83 e6 [2] c4 f7 [2] 8a fb [2] 86 f1 [2] 91 fa [2] 8a b4 [2] b7 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e894 {
  strings:
    $key_e894 = { bc fc [2] c8 e4 [2] 8f e6 [2] c8 f7 [2] 86 fb [2] 8a f1 [2] 9d fa [2] 86 b4 [2] bb }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2894 {
  strings:
    $key_2894 = { 7c fc [2] 08 e4 [2] 4f e6 [2] 08 f7 [2] 46 fb [2] 4a f1 [2] 5d fa [2] 46 b4 [2] 7b }

  condition:
    any of them
}
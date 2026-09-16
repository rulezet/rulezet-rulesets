rule TTP_XOR_MULT_DOSStub_2195 {
  strings:
    $key_2195 = { 75 fd [2] 01 e5 [2] 46 e7 [2] 01 f6 [2] 4f fa [2] 43 f0 [2] 54 fb [2] 4f b5 [2] 72 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3194 {
  strings:
    $key_3194 = { 65 fc [2] 11 e4 [2] 56 e6 [2] 11 f7 [2] 5f fb [2] 53 f1 [2] 44 fa [2] 5f b4 [2] 62 }

  condition:
    any of them
}
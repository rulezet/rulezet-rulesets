rule TTP_XOR_MULT_DOSStub_e994 {
  strings:
    $key_e994 = { bd fc [2] c9 e4 [2] 8e e6 [2] c9 f7 [2] 87 fb [2] 8b f1 [2] 9c fa [2] 87 b4 [2] ba }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f992 {
  strings:
    $key_f992 = { ad fa [2] d9 e2 [2] 9e e0 [2] d9 f1 [2] 97 fd [2] 9b f7 [2] 8c fc [2] 97 b2 [2] aa }

  condition:
    any of them
}
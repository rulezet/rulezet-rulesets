rule TTP_XOR_MULT_DOSStub_f993 {
  strings:
    $key_f993 = { ad fb [2] d9 e3 [2] 9e e1 [2] d9 f0 [2] 97 fc [2] 9b f6 [2] 8c fd [2] 97 b3 [2] aa }

  condition:
    any of them
}
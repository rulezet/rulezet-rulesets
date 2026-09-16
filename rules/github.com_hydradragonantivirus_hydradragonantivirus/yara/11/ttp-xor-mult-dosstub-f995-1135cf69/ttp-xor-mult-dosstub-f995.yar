rule TTP_XOR_MULT_DOSStub_f995 {
  strings:
    $key_f995 = { ad fd [2] d9 e5 [2] 9e e7 [2] d9 f6 [2] 97 fa [2] 9b f0 [2] 8c fb [2] 97 b5 [2] aa }

  condition:
    any of them
}
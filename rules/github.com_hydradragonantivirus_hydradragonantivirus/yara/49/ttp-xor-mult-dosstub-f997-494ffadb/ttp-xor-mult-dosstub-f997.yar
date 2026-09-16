rule TTP_XOR_MULT_DOSStub_f997 {
  strings:
    $key_f997 = { ad ff [2] d9 e7 [2] 9e e5 [2] d9 f4 [2] 97 f8 [2] 9b f2 [2] 8c f9 [2] 97 b7 [2] aa }

  condition:
    any of them
}
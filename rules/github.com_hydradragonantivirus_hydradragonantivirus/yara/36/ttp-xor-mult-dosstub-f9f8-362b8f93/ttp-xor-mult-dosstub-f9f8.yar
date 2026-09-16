rule TTP_XOR_MULT_DOSStub_f9f8 {
  strings:
    $key_f9f8 = { ad 90 [2] d9 88 [2] 9e 8a [2] d9 9b [2] 97 97 [2] 9b 9d [2] 8c 96 [2] 97 d8 [2] aa }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f9fa {
  strings:
    $key_f9fa = { ad 92 [2] d9 8a [2] 9e 88 [2] d9 99 [2] 97 95 [2] 9b 9f [2] 8c 94 [2] 97 da [2] aa }

  condition:
    any of them
}
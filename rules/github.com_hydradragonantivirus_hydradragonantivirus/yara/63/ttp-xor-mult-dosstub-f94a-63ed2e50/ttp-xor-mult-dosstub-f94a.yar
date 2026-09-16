rule TTP_XOR_MULT_DOSStub_f94a {
  strings:
    $key_f94a = { ad 22 [2] d9 3a [2] 9e 38 [2] d9 29 [2] 97 25 [2] 9b 2f [2] 8c 24 [2] 97 6a [2] aa }

  condition:
    any of them
}
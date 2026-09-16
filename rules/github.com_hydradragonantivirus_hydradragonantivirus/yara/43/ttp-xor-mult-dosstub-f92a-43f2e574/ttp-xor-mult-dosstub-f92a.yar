rule TTP_XOR_MULT_DOSStub_f92a {
  strings:
    $key_f92a = { ad 42 [2] d9 5a [2] 9e 58 [2] d9 49 [2] 97 45 [2] 9b 4f [2] 8c 44 [2] 97 0a [2] aa }

  condition:
    any of them
}
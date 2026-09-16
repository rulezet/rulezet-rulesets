rule TTP_XOR_MULT_DOSStub_f91a {
  strings:
    $key_f91a = { ad 72 [2] d9 6a [2] 9e 68 [2] d9 79 [2] 97 75 [2] 9b 7f [2] 8c 74 [2] 97 3a [2] aa }

  condition:
    any of them
}
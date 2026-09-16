rule TTP_XOR_MULT_DOSStub_f97f {
  strings:
    $key_f97f = { ad 17 [2] d9 0f [2] 9e 0d [2] d9 1c [2] 97 10 [2] 9b 1a [2] 8c 11 [2] 97 5f [2] aa }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f97d {
  strings:
    $key_f97d = { ad 15 [2] d9 0d [2] 9e 0f [2] d9 1e [2] 97 12 [2] 9b 18 [2] 8c 13 [2] 97 5d [2] aa }

  condition:
    any of them
}
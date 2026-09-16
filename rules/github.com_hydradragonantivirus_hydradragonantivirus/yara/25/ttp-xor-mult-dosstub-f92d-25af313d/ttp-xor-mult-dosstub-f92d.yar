rule TTP_XOR_MULT_DOSStub_f92d {
  strings:
    $key_f92d = { ad 45 [2] d9 5d [2] 9e 5f [2] d9 4e [2] 97 42 [2] 9b 48 [2] 8c 43 [2] 97 0d [2] aa }

  condition:
    any of them
}
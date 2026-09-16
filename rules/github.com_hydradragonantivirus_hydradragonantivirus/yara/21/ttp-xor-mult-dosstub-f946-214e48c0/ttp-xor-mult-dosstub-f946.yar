rule TTP_XOR_MULT_DOSStub_f946 {
  strings:
    $key_f946 = { ad 2e [2] d9 36 [2] 9e 34 [2] d9 25 [2] 97 29 [2] 9b 23 [2] 8c 28 [2] 97 66 [2] aa }

  condition:
    any of them
}
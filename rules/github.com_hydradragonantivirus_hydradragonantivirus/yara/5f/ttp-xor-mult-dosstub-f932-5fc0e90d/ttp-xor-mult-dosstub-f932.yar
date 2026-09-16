rule TTP_XOR_MULT_DOSStub_f932 {
  strings:
    $key_f932 = { ad 5a [2] d9 42 [2] 9e 40 [2] d9 51 [2] 97 5d [2] 9b 57 [2] 8c 5c [2] 97 12 [2] aa }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f9f1 {
  strings:
    $key_f9f1 = { ad 99 [2] d9 81 [2] 9e 83 [2] d9 92 [2] 97 9e [2] 9b 94 [2] 8c 9f [2] 97 d1 [2] aa }

  condition:
    any of them
}
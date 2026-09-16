rule TTP_XOR_MULT_DOSStub_f960 {
  strings:
    $key_f960 = { ad 08 [2] d9 10 [2] 9e 12 [2] d9 03 [2] 97 0f [2] 9b 05 [2] 8c 0e [2] 97 40 [2] aa }

  condition:
    any of them
}
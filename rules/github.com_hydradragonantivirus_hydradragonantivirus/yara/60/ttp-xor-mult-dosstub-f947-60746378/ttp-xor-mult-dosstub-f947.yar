rule TTP_XOR_MULT_DOSStub_f947 {
  strings:
    $key_f947 = { ad 2f [2] d9 37 [2] 9e 35 [2] d9 24 [2] 97 28 [2] 9b 22 [2] 8c 29 [2] 97 67 [2] aa }

  condition:
    any of them
}
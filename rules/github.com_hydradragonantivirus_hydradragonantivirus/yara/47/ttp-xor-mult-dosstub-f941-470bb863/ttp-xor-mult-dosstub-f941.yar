rule TTP_XOR_MULT_DOSStub_f941 {
  strings:
    $key_f941 = { ad 29 [2] d9 31 [2] 9e 33 [2] d9 22 [2] 97 2e [2] 9b 24 [2] 8c 2f [2] 97 61 [2] aa }

  condition:
    any of them
}
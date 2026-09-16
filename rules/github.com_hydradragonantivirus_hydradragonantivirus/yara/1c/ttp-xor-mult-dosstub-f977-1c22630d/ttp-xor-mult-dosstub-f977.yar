rule TTP_XOR_MULT_DOSStub_f977 {
  strings:
    $key_f977 = { ad 1f [2] d9 07 [2] 9e 05 [2] d9 14 [2] 97 18 [2] 9b 12 [2] 8c 19 [2] 97 57 [2] aa }

  condition:
    any of them
}
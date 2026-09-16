rule TTP_XOR_MULT_DOSStub_f927 {
  strings:
    $key_f927 = { ad 4f [2] d9 57 [2] 9e 55 [2] d9 44 [2] 97 48 [2] 9b 42 [2] 8c 49 [2] 97 07 [2] aa }

  condition:
    any of them
}
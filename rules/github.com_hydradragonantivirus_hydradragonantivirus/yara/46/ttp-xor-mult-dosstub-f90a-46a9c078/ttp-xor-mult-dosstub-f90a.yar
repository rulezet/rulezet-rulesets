rule TTP_XOR_MULT_DOSStub_f90a {
  strings:
    $key_f90a = { ad 62 [2] d9 7a [2] 9e 78 [2] d9 69 [2] 97 65 [2] 9b 6f [2] 8c 64 [2] 97 2a [2] aa }

  condition:
    any of them
}
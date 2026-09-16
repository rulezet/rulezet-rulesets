rule TTP_XOR_MULT_DOSStub_f957 {
  strings:
    $key_f957 = { ad 3f [2] d9 27 [2] 9e 25 [2] d9 34 [2] 97 38 [2] 9b 32 [2] 8c 39 [2] 97 77 [2] aa }

  condition:
    any of them
}
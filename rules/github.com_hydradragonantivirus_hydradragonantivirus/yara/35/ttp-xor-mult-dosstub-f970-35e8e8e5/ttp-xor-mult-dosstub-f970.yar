rule TTP_XOR_MULT_DOSStub_f970 {
  strings:
    $key_f970 = { ad 18 [2] d9 00 [2] 9e 02 [2] d9 13 [2] 97 1f [2] 9b 15 [2] 8c 1e [2] 97 50 [2] aa }

  condition:
    any of them
}
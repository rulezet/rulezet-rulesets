rule TTP_XOR_MULT_DOSStub_f907 {
  strings:
    $key_f907 = { ad 6f [2] d9 77 [2] 9e 75 [2] d9 64 [2] 97 68 [2] 9b 62 [2] 8c 69 [2] 97 27 [2] aa }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f9f0 {
  strings:
    $key_f9f0 = { ad 98 [2] d9 80 [2] 9e 82 [2] d9 93 [2] 97 9f [2] 9b 95 [2] 8c 9e [2] 97 d0 [2] aa }

  condition:
    any of them
}
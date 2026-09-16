rule TTP_XOR_MULT_DOSStub_f9f6 {
  strings:
    $key_f9f6 = { ad 9e [2] d9 86 [2] 9e 84 [2] d9 95 [2] 97 99 [2] 9b 93 [2] 8c 98 [2] 97 d6 [2] aa }

  condition:
    any of them
}
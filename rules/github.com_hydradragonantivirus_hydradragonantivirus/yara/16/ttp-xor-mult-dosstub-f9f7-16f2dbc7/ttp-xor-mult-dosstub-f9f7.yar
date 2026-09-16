rule TTP_XOR_MULT_DOSStub_f9f7 {
  strings:
    $key_f9f7 = { ad 9f [2] d9 87 [2] 9e 85 [2] d9 94 [2] 97 98 [2] 9b 92 [2] 8c 99 [2] 97 d7 [2] aa }

  condition:
    any of them
}
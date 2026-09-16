rule TTP_XOR_MULT_DOSStub_f9e1 {
  strings:
    $key_f9e1 = { ad 89 [2] d9 91 [2] 9e 93 [2] d9 82 [2] 97 8e [2] 9b 84 [2] 8c 8f [2] 97 c1 [2] aa }

  condition:
    any of them
}
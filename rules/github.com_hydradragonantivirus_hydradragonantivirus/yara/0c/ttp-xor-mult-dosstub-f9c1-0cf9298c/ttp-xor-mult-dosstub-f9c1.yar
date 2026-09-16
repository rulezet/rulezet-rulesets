rule TTP_XOR_MULT_DOSStub_f9c1 {
  strings:
    $key_f9c1 = { ad a9 [2] d9 b1 [2] 9e b3 [2] d9 a2 [2] 97 ae [2] 9b a4 [2] 8c af [2] 97 e1 [2] aa }

  condition:
    any of them
}
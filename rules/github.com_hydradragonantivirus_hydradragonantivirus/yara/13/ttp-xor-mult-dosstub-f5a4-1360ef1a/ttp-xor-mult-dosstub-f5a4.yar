rule TTP_XOR_MULT_DOSStub_f5a4 {
  strings:
    $key_f5a4 = { a1 cc [2] d5 d4 [2] 92 d6 [2] d5 c7 [2] 9b cb [2] 97 c1 [2] 80 ca [2] 9b 84 [2] a6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f5a9 {
  strings:
    $key_f5a9 = { a1 c1 [2] d5 d9 [2] 92 db [2] d5 ca [2] 9b c6 [2] 97 cc [2] 80 c7 [2] 9b 89 [2] a6 }

  condition:
    any of them
}
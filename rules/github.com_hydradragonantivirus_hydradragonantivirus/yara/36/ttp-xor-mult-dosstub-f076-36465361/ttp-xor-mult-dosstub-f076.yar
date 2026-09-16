rule TTP_XOR_MULT_DOSStub_f076 {
  strings:
    $key_f076 = { a4 1e [2] d0 06 [2] 97 04 [2] d0 15 [2] 9e 19 [2] 92 13 [2] 85 18 [2] 9e 56 [2] a3 }

  condition:
    any of them
}
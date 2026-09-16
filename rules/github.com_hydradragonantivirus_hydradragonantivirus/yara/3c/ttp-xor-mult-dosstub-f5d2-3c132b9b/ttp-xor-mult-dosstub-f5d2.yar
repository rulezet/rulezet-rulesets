rule TTP_XOR_MULT_DOSStub_f5d2 {
  strings:
    $key_f5d2 = { a1 ba [2] d5 a2 [2] 92 a0 [2] d5 b1 [2] 9b bd [2] 97 b7 [2] 80 bc [2] 9b f2 [2] a6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f4a4 {
  strings:
    $key_f4a4 = { a0 cc [2] d4 d4 [2] 93 d6 [2] d4 c7 [2] 9a cb [2] 96 c1 [2] 81 ca [2] 9a 84 [2] a7 }

  condition:
    any of them
}
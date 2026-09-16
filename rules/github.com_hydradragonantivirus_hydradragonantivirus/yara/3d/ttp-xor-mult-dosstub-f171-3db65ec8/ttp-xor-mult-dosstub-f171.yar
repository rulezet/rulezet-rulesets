rule TTP_XOR_MULT_DOSStub_f171 {
  strings:
    $key_f171 = { a5 19 [2] d1 01 [2] 96 03 [2] d1 12 [2] 9f 1e [2] 93 14 [2] 84 1f [2] 9f 51 [2] a2 }

  condition:
    any of them
}
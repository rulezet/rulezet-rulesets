rule TTP_XOR_MULT_DOSStub_f136 {
  strings:
    $key_f136 = { a5 5e [2] d1 46 [2] 96 44 [2] d1 55 [2] 9f 59 [2] 93 53 [2] 84 58 [2] 9f 16 [2] a2 }

  condition:
    any of them
}
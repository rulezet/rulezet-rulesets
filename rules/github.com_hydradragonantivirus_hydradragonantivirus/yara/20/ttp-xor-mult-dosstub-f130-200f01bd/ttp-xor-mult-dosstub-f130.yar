rule TTP_XOR_MULT_DOSStub_f130 {
  strings:
    $key_f130 = { a5 58 [2] d1 40 [2] 96 42 [2] d1 53 [2] 9f 5f [2] 93 55 [2] 84 5e [2] 9f 10 [2] a2 }

  condition:
    any of them
}
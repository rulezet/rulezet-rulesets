rule TTP_XOR_MULT_DOSStub_f231 {
  strings:
    $key_f231 = { a6 59 [2] d2 41 [2] 95 43 [2] d2 52 [2] 9c 5e [2] 90 54 [2] 87 5f [2] 9c 11 [2] a1 }

  condition:
    any of them
}
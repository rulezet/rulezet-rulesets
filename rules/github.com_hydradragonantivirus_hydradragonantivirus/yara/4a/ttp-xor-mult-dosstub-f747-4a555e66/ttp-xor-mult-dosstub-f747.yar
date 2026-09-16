rule TTP_XOR_MULT_DOSStub_f747 {
  strings:
    $key_f747 = { a3 2f [2] d7 37 [2] 90 35 [2] d7 24 [2] 99 28 [2] 95 22 [2] 82 29 [2] 99 67 [2] a4 }

  condition:
    any of them
}
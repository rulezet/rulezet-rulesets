rule TTP_XOR_MULT_DOSStub_f260 {
  strings:
    $key_f260 = { a6 08 [2] d2 10 [2] 95 12 [2] d2 03 [2] 9c 0f [2] 90 05 [2] 87 0e [2] 9c 40 [2] a1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f266 {
  strings:
    $key_f266 = { a6 0e [2] d2 16 [2] 95 14 [2] d2 05 [2] 9c 09 [2] 90 03 [2] 87 08 [2] 9c 46 [2] a1 }

  condition:
    any of them
}
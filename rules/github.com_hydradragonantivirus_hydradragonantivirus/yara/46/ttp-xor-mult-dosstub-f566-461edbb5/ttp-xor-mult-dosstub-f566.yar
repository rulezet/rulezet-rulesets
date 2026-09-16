rule TTP_XOR_MULT_DOSStub_f566 {
  strings:
    $key_f566 = { a1 0e [2] d5 16 [2] 92 14 [2] d5 05 [2] 9b 09 [2] 97 03 [2] 80 08 [2] 9b 46 [2] a6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f571 {
  strings:
    $key_f571 = { a1 19 [2] d5 01 [2] 92 03 [2] d5 12 [2] 9b 1e [2] 97 14 [2] 80 1f [2] 9b 51 [2] a6 }

  condition:
    any of them
}
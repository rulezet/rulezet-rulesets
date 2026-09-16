rule TTP_XOR_MULT_DOSStub_f206 {
  strings:
    $key_f206 = { a6 6e [2] d2 76 [2] 95 74 [2] d2 65 [2] 9c 69 [2] 90 63 [2] 87 68 [2] 9c 26 [2] a1 }

  condition:
    any of them
}
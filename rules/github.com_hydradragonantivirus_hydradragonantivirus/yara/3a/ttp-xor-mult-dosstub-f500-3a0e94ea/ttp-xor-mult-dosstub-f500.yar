rule TTP_XOR_MULT_DOSStub_f500 {
  strings:
    $key_f500 = { a1 68 [2] d5 70 [2] 92 72 [2] d5 63 [2] 9b 6f [2] 97 65 [2] 80 6e [2] 9b 20 [2] a6 }

  condition:
    any of them
}
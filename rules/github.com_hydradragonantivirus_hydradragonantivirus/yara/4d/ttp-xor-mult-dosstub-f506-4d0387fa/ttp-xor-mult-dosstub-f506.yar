rule TTP_XOR_MULT_DOSStub_f506 {
  strings:
    $key_f506 = { a1 6e [2] d5 76 [2] 92 74 [2] d5 65 [2] 9b 69 [2] 97 63 [2] 80 68 [2] 9b 26 [2] a6 }

  condition:
    any of them
}
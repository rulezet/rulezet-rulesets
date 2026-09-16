rule TTP_XOR_MULT_DOSStub_f5e6 {
  strings:
    $key_f5e6 = { a1 8e [2] d5 96 [2] 92 94 [2] d5 85 [2] 9b 89 [2] 97 83 [2] 80 88 [2] 9b c6 [2] a6 }

  condition:
    any of them
}
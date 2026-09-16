rule TTP_XOR_MULT_DOSStub_f5f0 {
  strings:
    $key_f5f0 = { a1 98 [2] d5 80 [2] 92 82 [2] d5 93 [2] 9b 9f [2] 97 95 [2] 80 9e [2] 9b d0 [2] a6 }

  condition:
    any of them
}
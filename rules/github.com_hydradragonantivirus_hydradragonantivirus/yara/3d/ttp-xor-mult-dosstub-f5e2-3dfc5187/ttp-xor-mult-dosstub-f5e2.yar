rule TTP_XOR_MULT_DOSStub_f5e2 {
  strings:
    $key_f5e2 = { a1 8a [2] d5 92 [2] 92 90 [2] d5 81 [2] 9b 8d [2] 97 87 [2] 80 8c [2] 9b c2 [2] a6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f2e6 {
  strings:
    $key_f2e6 = { a6 8e [2] d2 96 [2] 95 94 [2] d2 85 [2] 9c 89 [2] 90 83 [2] 87 88 [2] 9c c6 [2] a1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f2e0 {
  strings:
    $key_f2e0 = { a6 88 [2] d2 90 [2] 95 92 [2] d2 83 [2] 9c 8f [2] 90 85 [2] 87 8e [2] 9c c0 [2] a1 }

  condition:
    any of them
}
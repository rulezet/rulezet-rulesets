rule TTP_XOR_MULT_DOSStub_f2e1 {
  strings:
    $key_f2e1 = { a6 89 [2] d2 91 [2] 95 93 [2] d2 82 [2] 9c 8e [2] 90 84 [2] 87 8f [2] 9c c1 [2] a1 }

  condition:
    any of them
}
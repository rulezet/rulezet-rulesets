rule TTP_XOR_MULT_DOSStub_f251 {
  strings:
    $key_f251 = { a6 39 [2] d2 21 [2] 95 23 [2] d2 32 [2] 9c 3e [2] 90 34 [2] 87 3f [2] 9c 71 [2] a1 }

  condition:
    any of them
}
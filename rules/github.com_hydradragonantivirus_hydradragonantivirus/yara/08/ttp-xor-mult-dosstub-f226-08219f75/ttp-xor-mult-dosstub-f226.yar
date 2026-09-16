rule TTP_XOR_MULT_DOSStub_f226 {
  strings:
    $key_f226 = { a6 4e [2] d2 56 [2] 95 54 [2] d2 45 [2] 9c 49 [2] 90 43 [2] 87 48 [2] 9c 06 [2] a1 }

  condition:
    any of them
}
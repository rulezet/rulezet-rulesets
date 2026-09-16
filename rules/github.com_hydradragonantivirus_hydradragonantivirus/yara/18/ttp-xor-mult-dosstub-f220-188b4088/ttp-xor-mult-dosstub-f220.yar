rule TTP_XOR_MULT_DOSStub_f220 {
  strings:
    $key_f220 = { a6 48 [2] d2 50 [2] 95 52 [2] d2 43 [2] 9c 4f [2] 90 45 [2] 87 4e [2] 9c 00 [2] a1 }

  condition:
    any of them
}
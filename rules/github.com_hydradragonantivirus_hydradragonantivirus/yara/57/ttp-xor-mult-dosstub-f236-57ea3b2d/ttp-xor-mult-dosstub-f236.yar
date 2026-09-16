rule TTP_XOR_MULT_DOSStub_f236 {
  strings:
    $key_f236 = { a6 5e [2] d2 46 [2] 95 44 [2] d2 55 [2] 9c 59 [2] 90 53 [2] 87 58 [2] 9c 16 [2] a1 }

  condition:
    any of them
}
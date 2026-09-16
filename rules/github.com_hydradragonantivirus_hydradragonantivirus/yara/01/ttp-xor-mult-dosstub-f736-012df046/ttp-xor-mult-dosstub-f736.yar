rule TTP_XOR_MULT_DOSStub_f736 {
  strings:
    $key_f736 = { a3 5e [2] d7 46 [2] 90 44 [2] d7 55 [2] 99 59 [2] 95 53 [2] 82 58 [2] 99 16 [2] a4 }

  condition:
    any of them
}
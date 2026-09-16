rule TTP_XOR_MULT_DOSStub_f720 {
  strings:
    $key_f720 = { a3 48 [2] d7 50 [2] 90 52 [2] d7 43 [2] 99 4f [2] 95 45 [2] 82 4e [2] 99 00 [2] a4 }

  condition:
    any of them
}
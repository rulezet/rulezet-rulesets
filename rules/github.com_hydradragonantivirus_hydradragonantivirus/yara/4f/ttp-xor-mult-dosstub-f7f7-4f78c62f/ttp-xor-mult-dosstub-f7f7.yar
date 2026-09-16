rule TTP_XOR_MULT_DOSStub_f7f7 {
  strings:
    $key_f7f7 = { a3 9f [2] d7 87 [2] 90 85 [2] d7 94 [2] 99 98 [2] 95 92 [2] 82 99 [2] 99 d7 [2] a4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f751 {
  strings:
    $key_f751 = { a3 39 [2] d7 21 [2] 90 23 [2] d7 32 [2] 99 3e [2] 95 34 [2] 82 3f [2] 99 71 [2] a4 }

  condition:
    any of them
}
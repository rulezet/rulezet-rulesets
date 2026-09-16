rule TTP_XOR_MULT_DOSStub_f757 {
  strings:
    $key_f757 = { a3 3f [2] d7 27 [2] 90 25 [2] d7 34 [2] 99 38 [2] 95 32 [2] 82 39 [2] 99 77 [2] a4 }

  condition:
    any of them
}
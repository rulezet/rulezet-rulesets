rule TTP_XOR_MULT_DOSStub_f773 {
  strings:
    $key_f773 = { a3 1b [2] d7 03 [2] 90 01 [2] d7 10 [2] 99 1c [2] 95 16 [2] 82 1d [2] 99 53 [2] a4 }

  condition:
    any of them
}
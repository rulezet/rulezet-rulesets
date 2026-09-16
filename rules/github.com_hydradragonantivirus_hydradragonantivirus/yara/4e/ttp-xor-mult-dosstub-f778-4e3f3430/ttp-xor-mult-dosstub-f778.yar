rule TTP_XOR_MULT_DOSStub_f778 {
  strings:
    $key_f778 = { a3 10 [2] d7 08 [2] 90 0a [2] d7 1b [2] 99 17 [2] 95 1d [2] 82 16 [2] 99 58 [2] a4 }

  condition:
    any of them
}
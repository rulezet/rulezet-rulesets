rule TTP_XOR_MULT_DOSStub_f765 {
  strings:
    $key_f765 = { a3 0d [2] d7 15 [2] 90 17 [2] d7 06 [2] 99 0a [2] 95 00 [2] 82 0b [2] 99 45 [2] a4 }

  condition:
    any of them
}
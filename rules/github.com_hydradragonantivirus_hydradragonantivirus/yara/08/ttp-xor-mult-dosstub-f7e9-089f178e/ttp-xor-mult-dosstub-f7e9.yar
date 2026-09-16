rule TTP_XOR_MULT_DOSStub_f7e9 {
  strings:
    $key_f7e9 = { a3 81 [2] d7 99 [2] 90 9b [2] d7 8a [2] 99 86 [2] 95 8c [2] 82 87 [2] 99 c9 [2] a4 }

  condition:
    any of them
}
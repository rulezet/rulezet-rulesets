rule TTP_XOR_MULT_DOSStub_f7f5 {
  strings:
    $key_f7f5 = { a3 9d [2] d7 85 [2] 90 87 [2] d7 96 [2] 99 9a [2] 95 90 [2] 82 9b [2] 99 d5 [2] a4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f703 {
  strings:
    $key_f703 = { a3 6b [2] d7 73 [2] 90 71 [2] d7 60 [2] 99 6c [2] 95 66 [2] 82 6d [2] 99 23 [2] a4 }

  condition:
    any of them
}
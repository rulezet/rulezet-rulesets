rule TTP_XOR_MULT_DOSStub_f759 {
  strings:
    $key_f759 = { a3 31 [2] d7 29 [2] 90 2b [2] d7 3a [2] 99 36 [2] 95 3c [2] 82 37 [2] 99 79 [2] a4 }

  condition:
    any of them
}
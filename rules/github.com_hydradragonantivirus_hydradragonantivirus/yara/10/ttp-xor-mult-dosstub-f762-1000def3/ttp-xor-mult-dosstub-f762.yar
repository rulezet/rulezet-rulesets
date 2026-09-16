rule TTP_XOR_MULT_DOSStub_f762 {
  strings:
    $key_f762 = { a3 0a [2] d7 12 [2] 90 10 [2] d7 01 [2] 99 0d [2] 95 07 [2] 82 0c [2] 99 42 [2] a4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f769 {
  strings:
    $key_f769 = { a3 01 [2] d7 19 [2] 90 1b [2] d7 0a [2] 99 06 [2] 95 0c [2] 82 07 [2] 99 49 [2] a4 }

  condition:
    any of them
}
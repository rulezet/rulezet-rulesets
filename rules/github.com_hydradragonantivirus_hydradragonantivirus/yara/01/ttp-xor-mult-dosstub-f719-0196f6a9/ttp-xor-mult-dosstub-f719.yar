rule TTP_XOR_MULT_DOSStub_f719 {
  strings:
    $key_f719 = { a3 71 [2] d7 69 [2] 90 6b [2] d7 7a [2] 99 76 [2] 95 7c [2] 82 77 [2] 99 39 [2] a4 }

  condition:
    any of them
}
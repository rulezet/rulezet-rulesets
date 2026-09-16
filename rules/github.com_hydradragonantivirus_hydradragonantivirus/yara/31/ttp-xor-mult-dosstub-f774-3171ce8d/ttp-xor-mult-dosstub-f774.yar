rule TTP_XOR_MULT_DOSStub_f774 {
  strings:
    $key_f774 = { a3 1c [2] d7 04 [2] 90 06 [2] d7 17 [2] 99 1b [2] 95 11 [2] 82 1a [2] 99 54 [2] a4 }

  condition:
    any of them
}
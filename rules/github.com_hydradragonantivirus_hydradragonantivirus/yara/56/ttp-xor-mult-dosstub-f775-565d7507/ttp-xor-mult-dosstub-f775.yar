rule TTP_XOR_MULT_DOSStub_f775 {
  strings:
    $key_f775 = { a3 1d [2] d7 05 [2] 90 07 [2] d7 16 [2] 99 1a [2] 95 10 [2] 82 1b [2] 99 55 [2] a4 }

  condition:
    any of them
}
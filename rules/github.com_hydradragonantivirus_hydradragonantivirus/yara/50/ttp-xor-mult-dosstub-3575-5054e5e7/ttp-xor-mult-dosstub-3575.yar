rule TTP_XOR_MULT_DOSStub_3575 {
  strings:
    $key_3575 = { 61 1d [2] 15 05 [2] 52 07 [2] 15 16 [2] 5b 1a [2] 57 10 [2] 40 1b [2] 5b 55 [2] 66 }

  condition:
    any of them
}
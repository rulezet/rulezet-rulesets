rule TTP_XOR_MULT_DOSStub_4575 {
  strings:
    $key_4575 = { 11 1d [2] 65 05 [2] 22 07 [2] 65 16 [2] 2b 1a [2] 27 10 [2] 30 1b [2] 2b 55 [2] 16 }

  condition:
    any of them
}
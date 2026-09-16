rule TTP_XOR_MULT_DOSStub_7575 {
  strings:
    $key_7575 = { 21 1d [2] 55 05 [2] 12 07 [2] 55 16 [2] 1b 1a [2] 17 10 [2] 00 1b [2] 1b 55 [2] 26 }

  condition:
    any of them
}
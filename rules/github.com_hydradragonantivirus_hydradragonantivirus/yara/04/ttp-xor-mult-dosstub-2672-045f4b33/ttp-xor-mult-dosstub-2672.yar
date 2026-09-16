rule TTP_XOR_MULT_DOSStub_2672 {
  strings:
    $key_2672 = { 72 1a [2] 06 02 [2] 41 00 [2] 06 11 [2] 48 1d [2] 44 17 [2] 53 1c [2] 48 52 [2] 75 }

  condition:
    any of them
}
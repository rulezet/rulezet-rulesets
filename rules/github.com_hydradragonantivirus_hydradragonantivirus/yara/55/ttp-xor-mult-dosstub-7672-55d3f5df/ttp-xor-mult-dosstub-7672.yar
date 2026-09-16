rule TTP_XOR_MULT_DOSStub_7672 {
  strings:
    $key_7672 = { 22 1a [2] 56 02 [2] 11 00 [2] 56 11 [2] 18 1d [2] 14 17 [2] 03 1c [2] 18 52 [2] 25 }

  condition:
    any of them
}
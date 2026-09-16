rule TTP_XOR_MULT_DOSStub_7675 {
  strings:
    $key_7675 = { 22 1d [2] 56 05 [2] 11 07 [2] 56 16 [2] 18 1a [2] 14 10 [2] 03 1b [2] 18 55 [2] 25 }

  condition:
    any of them
}
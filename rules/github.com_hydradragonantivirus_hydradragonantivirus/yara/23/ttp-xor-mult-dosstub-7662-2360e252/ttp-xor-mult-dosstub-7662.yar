rule TTP_XOR_MULT_DOSStub_7662 {
  strings:
    $key_7662 = { 22 0a [2] 56 12 [2] 11 10 [2] 56 01 [2] 18 0d [2] 14 07 [2] 03 0c [2] 18 42 [2] 25 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7622 {
  strings:
    $key_7622 = { 22 4a [2] 56 52 [2] 11 50 [2] 56 41 [2] 18 4d [2] 14 47 [2] 03 4c [2] 18 02 [2] 25 }

  condition:
    any of them
}
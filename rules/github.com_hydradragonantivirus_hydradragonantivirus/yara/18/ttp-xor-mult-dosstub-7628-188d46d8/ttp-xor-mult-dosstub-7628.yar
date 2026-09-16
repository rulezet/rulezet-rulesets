rule TTP_XOR_MULT_DOSStub_7628 {
  strings:
    $key_7628 = { 22 40 [2] 56 58 [2] 11 5a [2] 56 4b [2] 18 47 [2] 14 4d [2] 03 46 [2] 18 08 [2] 25 }

  condition:
    any of them
}
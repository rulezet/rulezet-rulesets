rule TTP_XOR_MULT_DOSStub_7624 {
  strings:
    $key_7624 = { 22 4c [2] 56 54 [2] 11 56 [2] 56 47 [2] 18 4b [2] 14 41 [2] 03 4a [2] 18 04 [2] 25 }

  condition:
    any of them
}
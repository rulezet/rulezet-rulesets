rule TTP_XOR_MULT_DOSStub_467c {
  strings:
    $key_467c = { 12 14 [2] 66 0c [2] 21 0e [2] 66 1f [2] 28 13 [2] 24 19 [2] 33 12 [2] 28 5c [2] 15 }

  condition:
    any of them
}
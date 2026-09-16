rule TTP_XOR_MULT_DOSStub_467b {
  strings:
    $key_467b = { 12 13 [2] 66 0b [2] 21 09 [2] 66 18 [2] 28 14 [2] 24 1e [2] 33 15 [2] 28 5b [2] 15 }

  condition:
    any of them
}
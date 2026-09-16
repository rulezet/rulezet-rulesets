rule TTP_XOR_MULT_DOSStub_735b {
  strings:
    $key_735b = { 27 33 [2] 53 2b [2] 14 29 [2] 53 38 [2] 1d 34 [2] 11 3e [2] 06 35 [2] 1d 7b [2] 20 }

  condition:
    any of them
}
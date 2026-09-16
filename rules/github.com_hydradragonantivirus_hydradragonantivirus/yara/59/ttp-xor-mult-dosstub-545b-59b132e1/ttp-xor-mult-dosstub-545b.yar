rule TTP_XOR_MULT_DOSStub_545b {
  strings:
    $key_545b = { 00 33 [2] 74 2b [2] 33 29 [2] 74 38 [2] 3a 34 [2] 36 3e [2] 21 35 [2] 3a 7b [2] 07 }

  condition:
    any of them
}
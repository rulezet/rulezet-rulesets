rule TTP_XOR_MULT_DOSStub_546b {
  strings:
    $key_546b = { 00 03 [2] 74 1b [2] 33 19 [2] 74 08 [2] 3a 04 [2] 36 0e [2] 21 05 [2] 3a 4b [2] 07 }

  condition:
    any of them
}
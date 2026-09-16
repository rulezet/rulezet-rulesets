rule TTP_XOR_MULT_DOSStub_6574 {
  strings:
    $key_6574 = { 31 1c [2] 45 04 [2] 02 06 [2] 45 17 [2] 0b 1b [2] 07 11 [2] 10 1a [2] 0b 54 [2] 36 }

  condition:
    any of them
}
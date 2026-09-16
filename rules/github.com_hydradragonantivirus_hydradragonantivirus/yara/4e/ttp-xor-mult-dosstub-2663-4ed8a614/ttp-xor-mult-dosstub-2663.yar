rule TTP_XOR_MULT_DOSStub_2663 {
  strings:
    $key_2663 = { 72 0b [2] 06 13 [2] 41 11 [2] 06 00 [2] 48 0c [2] 44 06 [2] 53 0d [2] 48 43 [2] 75 }

  condition:
    any of them
}
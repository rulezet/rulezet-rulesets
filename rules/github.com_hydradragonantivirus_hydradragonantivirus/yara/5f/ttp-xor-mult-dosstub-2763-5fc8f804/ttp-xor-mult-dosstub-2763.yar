rule TTP_XOR_MULT_DOSStub_2763 {
  strings:
    $key_2763 = { 73 0b [2] 07 13 [2] 40 11 [2] 07 00 [2] 49 0c [2] 45 06 [2] 52 0d [2] 49 43 [2] 74 }

  condition:
    any of them
}
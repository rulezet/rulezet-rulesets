rule TTP_XOR_MULT_DOSStub_7763 {
  strings:
    $key_7763 = { 23 0b [2] 57 13 [2] 10 11 [2] 57 00 [2] 19 0c [2] 15 06 [2] 02 0d [2] 19 43 [2] 24 }

  condition:
    any of them
}
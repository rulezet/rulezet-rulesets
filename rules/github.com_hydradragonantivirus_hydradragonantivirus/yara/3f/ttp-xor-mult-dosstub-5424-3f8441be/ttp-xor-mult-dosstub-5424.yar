rule TTP_XOR_MULT_DOSStub_5424 {
  strings:
    $key_5424 = { 00 4c [2] 74 54 [2] 33 56 [2] 74 47 [2] 3a 4b [2] 36 41 [2] 21 4a [2] 3a 04 [2] 07 }

  condition:
    any of them
}
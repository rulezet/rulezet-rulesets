rule TTP_XOR_MULT_DOSStub_6704 {
  strings:
    $key_6704 = { 33 6c [2] 47 74 [2] 00 76 [2] 47 67 [2] 09 6b [2] 05 61 [2] 12 6a [2] 09 24 [2] 34 }

  condition:
    any of them
}
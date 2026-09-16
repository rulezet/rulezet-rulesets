rule TTP_XOR_MULT_DOSStub_6004 {
  strings:
    $key_6004 = { 34 6c [2] 40 74 [2] 07 76 [2] 40 67 [2] 0e 6b [2] 02 61 [2] 15 6a [2] 0e 24 [2] 33 }

  condition:
    any of them
}
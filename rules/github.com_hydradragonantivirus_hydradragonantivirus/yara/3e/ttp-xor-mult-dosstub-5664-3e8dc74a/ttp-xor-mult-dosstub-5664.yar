rule TTP_XOR_MULT_DOSStub_5664 {
  strings:
    $key_5664 = { 02 0c [2] 76 14 [2] 31 16 [2] 76 07 [2] 38 0b [2] 34 01 [2] 23 0a [2] 38 44 [2] 05 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6654 {
  strings:
    $key_6654 = { 32 3c [2] 46 24 [2] 01 26 [2] 46 37 [2] 08 3b [2] 04 31 [2] 13 3a [2] 08 74 [2] 35 }

  condition:
    any of them
}
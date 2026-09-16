rule TTP_XOR_MULT_DOSStub_2174 {
  strings:
    $key_2174 = { 75 1c [2] 01 04 [2] 46 06 [2] 01 17 [2] 4f 1b [2] 43 11 [2] 54 1a [2] 4f 54 [2] 72 }

  condition:
    any of them
}
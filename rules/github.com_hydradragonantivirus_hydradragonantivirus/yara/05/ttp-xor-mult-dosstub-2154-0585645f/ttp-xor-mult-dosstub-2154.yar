rule TTP_XOR_MULT_DOSStub_2154 {
  strings:
    $key_2154 = { 75 3c [2] 01 24 [2] 46 26 [2] 01 37 [2] 4f 3b [2] 43 31 [2] 54 3a [2] 4f 74 [2] 72 }

  condition:
    any of them
}
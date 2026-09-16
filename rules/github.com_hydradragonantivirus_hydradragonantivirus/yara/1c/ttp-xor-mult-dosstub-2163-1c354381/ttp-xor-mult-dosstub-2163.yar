rule TTP_XOR_MULT_DOSStub_2163 {
  strings:
    $key_2163 = { 75 0b [2] 01 13 [2] 46 11 [2] 01 00 [2] 4f 0c [2] 43 06 [2] 54 0d [2] 4f 43 [2] 72 }

  condition:
    any of them
}
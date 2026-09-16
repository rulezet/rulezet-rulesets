rule TTP_XOR_MULT_DOSStub_2179 {
  strings:
    $key_2179 = { 75 11 [2] 01 09 [2] 46 0b [2] 01 1a [2] 4f 16 [2] 43 1c [2] 54 17 [2] 4f 59 [2] 72 }

  condition:
    any of them
}
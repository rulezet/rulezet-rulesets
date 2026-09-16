rule TTP_XOR_MULT_DOSStub_2168 {
  strings:
    $key_2168 = { 75 00 [2] 01 18 [2] 46 1a [2] 01 0b [2] 4f 07 [2] 43 0d [2] 54 06 [2] 4f 48 [2] 72 }

  condition:
    any of them
}
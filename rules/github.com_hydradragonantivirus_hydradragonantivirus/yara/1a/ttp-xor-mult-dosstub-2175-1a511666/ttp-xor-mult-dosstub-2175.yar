rule TTP_XOR_MULT_DOSStub_2175 {
  strings:
    $key_2175 = { 75 1d [2] 01 05 [2] 46 07 [2] 01 16 [2] 4f 1a [2] 43 10 [2] 54 1b [2] 4f 55 [2] 72 }

  condition:
    any of them
}
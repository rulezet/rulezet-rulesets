rule TTP_XOR_MULT_DOSStub_2149 {
  strings:
    $key_2149 = { 75 21 [2] 01 39 [2] 46 3b [2] 01 2a [2] 4f 26 [2] 43 2c [2] 54 27 [2] 4f 69 [2] 72 }

  condition:
    any of them
}
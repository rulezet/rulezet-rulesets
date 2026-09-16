rule TTP_XOR_MULT_DOSStub_2119 {
  strings:
    $key_2119 = { 75 71 [2] 01 69 [2] 46 6b [2] 01 7a [2] 4f 76 [2] 43 7c [2] 54 77 [2] 4f 39 [2] 72 }

  condition:
    any of them
}
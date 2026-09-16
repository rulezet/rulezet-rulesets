rule TTP_XOR_MULT_DOSStub_2139 {
  strings:
    $key_2139 = { 75 51 [2] 01 49 [2] 46 4b [2] 01 5a [2] 4f 56 [2] 43 5c [2] 54 57 [2] 4f 19 [2] 72 }

  condition:
    any of them
}
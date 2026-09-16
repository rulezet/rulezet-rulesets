rule TTP_XOR_MULT_DOSStub_2134 {
  strings:
    $key_2134 = { 75 5c [2] 01 44 [2] 46 46 [2] 01 57 [2] 4f 5b [2] 43 51 [2] 54 5a [2] 4f 14 [2] 72 }

  condition:
    any of them
}
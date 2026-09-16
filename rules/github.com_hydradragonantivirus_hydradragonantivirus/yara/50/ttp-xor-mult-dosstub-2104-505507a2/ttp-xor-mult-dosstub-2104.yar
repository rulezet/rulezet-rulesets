rule TTP_XOR_MULT_DOSStub_2104 {
  strings:
    $key_2104 = { 75 6c [2] 01 74 [2] 46 76 [2] 01 67 [2] 4f 6b [2] 43 61 [2] 54 6a [2] 4f 24 [2] 72 }

  condition:
    any of them
}
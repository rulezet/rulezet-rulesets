rule TTP_XOR_MULT_DOSStub_4125 {
  strings:
    $key_4125 = { 15 4d [2] 61 55 [2] 26 57 [2] 61 46 [2] 2f 4a [2] 23 40 [2] 34 4b [2] 2f 05 [2] 12 }

  condition:
    any of them
}
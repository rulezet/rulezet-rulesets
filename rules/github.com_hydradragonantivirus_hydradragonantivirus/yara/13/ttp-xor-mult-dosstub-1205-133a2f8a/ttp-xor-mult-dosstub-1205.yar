rule TTP_XOR_MULT_DOSStub_1205 {
  strings:
    $key_1205 = { 46 6d [2] 32 75 [2] 75 77 [2] 32 66 [2] 7c 6a [2] 70 60 [2] 67 6b [2] 7c 25 [2] 41 }

  condition:
    any of them
}
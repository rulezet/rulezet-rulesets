rule TTP_XOR_MULT_DOSStub_1332 {
  strings:
    $key_1332 = { 47 5a [2] 33 42 [2] 74 40 [2] 33 51 [2] 7d 5d [2] 71 57 [2] 66 5c [2] 7d 12 [2] 40 }

  condition:
    any of them
}
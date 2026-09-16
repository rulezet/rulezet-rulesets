rule TTP_XOR_MULT_DOSStub_1333 {
  strings:
    $key_1333 = { 47 5b [2] 33 43 [2] 74 41 [2] 33 50 [2] 7d 5c [2] 71 56 [2] 66 5d [2] 7d 13 [2] 40 }

  condition:
    any of them
}
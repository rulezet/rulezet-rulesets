rule TTP_XOR_MULT_DOSStub_1339 {
  strings:
    $key_1339 = { 47 51 [2] 33 49 [2] 74 4b [2] 33 5a [2] 7d 56 [2] 71 5c [2] 66 57 [2] 7d 19 [2] 40 }

  condition:
    any of them
}
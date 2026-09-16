rule TTP_XOR_MULT_DOSStub_1323 {
  strings:
    $key_1323 = { 47 4b [2] 33 53 [2] 74 51 [2] 33 40 [2] 7d 4c [2] 71 46 [2] 66 4d [2] 7d 03 [2] 40 }

  condition:
    any of them
}
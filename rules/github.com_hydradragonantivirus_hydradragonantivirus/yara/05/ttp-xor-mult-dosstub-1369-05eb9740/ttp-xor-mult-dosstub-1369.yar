rule TTP_XOR_MULT_DOSStub_1369 {
  strings:
    $key_1369 = { 47 01 [2] 33 19 [2] 74 1b [2] 33 0a [2] 7d 06 [2] 71 0c [2] 66 07 [2] 7d 49 [2] 40 }

  condition:
    any of them
}
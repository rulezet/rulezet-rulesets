rule TTP_XOR_MULT_DOSStub_1329 {
  strings:
    $key_1329 = { 47 41 [2] 33 59 [2] 74 5b [2] 33 4a [2] 7d 46 [2] 71 4c [2] 66 47 [2] 7d 09 [2] 40 }

  condition:
    any of them
}
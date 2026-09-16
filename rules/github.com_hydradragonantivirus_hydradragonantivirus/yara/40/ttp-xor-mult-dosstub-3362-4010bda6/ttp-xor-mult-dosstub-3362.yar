rule TTP_XOR_MULT_DOSStub_3362 {
  strings:
    $key_3362 = { 67 0a [2] 13 12 [2] 54 10 [2] 13 01 [2] 5d 0d [2] 51 07 [2] 46 0c [2] 5d 42 [2] 60 }

  condition:
    any of them
}
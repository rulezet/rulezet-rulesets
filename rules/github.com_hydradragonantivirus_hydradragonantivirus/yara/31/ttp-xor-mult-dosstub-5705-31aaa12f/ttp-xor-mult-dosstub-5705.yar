rule TTP_XOR_MULT_DOSStub_5705 {
  strings:
    $key_5705 = { 03 6d [2] 77 75 [2] 30 77 [2] 77 66 [2] 39 6a [2] 35 60 [2] 22 6b [2] 39 25 [2] 04 }

  condition:
    any of them
}
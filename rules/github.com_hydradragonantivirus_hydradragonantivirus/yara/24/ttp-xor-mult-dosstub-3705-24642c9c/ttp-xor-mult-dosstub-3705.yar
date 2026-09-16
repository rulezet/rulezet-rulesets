rule TTP_XOR_MULT_DOSStub_3705 {
  strings:
    $key_3705 = { 63 6d [2] 17 75 [2] 50 77 [2] 17 66 [2] 59 6a [2] 55 60 [2] 42 6b [2] 59 25 [2] 64 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5518 {
  strings:
    $key_5518 = { 01 70 [2] 75 68 [2] 32 6a [2] 75 7b [2] 3b 77 [2] 37 7d [2] 20 76 [2] 3b 38 [2] 06 }

  condition:
    any of them
}
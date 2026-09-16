rule TTP_XOR_MULT_DOSStub_5718 {
  strings:
    $key_5718 = { 03 70 [2] 77 68 [2] 30 6a [2] 77 7b [2] 39 77 [2] 35 7d [2] 22 76 [2] 39 38 [2] 04 }

  condition:
    any of them
}
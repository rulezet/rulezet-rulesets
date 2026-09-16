rule TTP_XOR_MULT_DOSStub_5744 {
  strings:
    $key_5744 = { 03 2c [2] 77 34 [2] 30 36 [2] 77 27 [2] 39 2b [2] 35 21 [2] 22 2a [2] 39 64 [2] 04 }

  condition:
    any of them
}
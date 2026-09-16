rule TTP_XOR_MULT_DOSStub_5746 {
  strings:
    $key_5746 = { 03 2e [2] 77 36 [2] 30 34 [2] 77 25 [2] 39 29 [2] 35 23 [2] 22 28 [2] 39 66 [2] 04 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5706 {
  strings:
    $key_5706 = { 03 6e [2] 77 76 [2] 30 74 [2] 77 65 [2] 39 69 [2] 35 63 [2] 22 68 [2] 39 26 [2] 04 }

  condition:
    any of them
}
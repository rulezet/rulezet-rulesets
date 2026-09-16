rule TTP_XOR_MULT_DOSStub_1573 {
  strings:
    $key_1573 = { 41 1b [2] 35 03 [2] 72 01 [2] 35 10 [2] 7b 1c [2] 77 16 [2] 60 1d [2] 7b 53 [2] 46 }

  condition:
    any of them
}
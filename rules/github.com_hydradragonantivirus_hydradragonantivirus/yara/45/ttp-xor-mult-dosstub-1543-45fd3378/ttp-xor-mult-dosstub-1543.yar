rule TTP_XOR_MULT_DOSStub_1543 {
  strings:
    $key_1543 = { 41 2b [2] 35 33 [2] 72 31 [2] 35 20 [2] 7b 2c [2] 77 26 [2] 60 2d [2] 7b 63 [2] 46 }

  condition:
    any of them
}
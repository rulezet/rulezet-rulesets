rule TTP_XOR_MULT_DOSStub_1510 {
  strings:
    $key_1510 = { 41 78 [2] 35 60 [2] 72 62 [2] 35 73 [2] 7b 7f [2] 77 75 [2] 60 7e [2] 7b 30 [2] 46 }

  condition:
    any of them
}
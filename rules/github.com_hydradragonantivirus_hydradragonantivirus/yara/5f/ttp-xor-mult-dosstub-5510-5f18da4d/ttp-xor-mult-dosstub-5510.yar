rule TTP_XOR_MULT_DOSStub_5510 {
  strings:
    $key_5510 = { 01 78 [2] 75 60 [2] 32 62 [2] 75 73 [2] 3b 7f [2] 37 75 [2] 20 7e [2] 3b 30 [2] 06 }

  condition:
    any of them
}
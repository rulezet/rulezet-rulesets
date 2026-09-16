rule TTP_XOR_MULT_DOSStub_5210 {
  strings:
    $key_5210 = { 06 78 [2] 72 60 [2] 35 62 [2] 72 73 [2] 3c 7f [2] 30 75 [2] 27 7e [2] 3c 30 [2] 01 }

  condition:
    any of them
}
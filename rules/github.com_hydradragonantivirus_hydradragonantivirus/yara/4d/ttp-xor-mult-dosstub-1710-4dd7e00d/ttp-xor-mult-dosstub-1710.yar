rule TTP_XOR_MULT_DOSStub_1710 {
  strings:
    $key_1710 = { 43 78 [2] 37 60 [2] 70 62 [2] 37 73 [2] 79 7f [2] 75 75 [2] 62 7e [2] 79 30 [2] 44 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4010 {
  strings:
    $key_4010 = { 14 78 [2] 60 60 [2] 27 62 [2] 60 73 [2] 2e 7f [2] 22 75 [2] 35 7e [2] 2e 30 [2] 13 }

  condition:
    any of them
}
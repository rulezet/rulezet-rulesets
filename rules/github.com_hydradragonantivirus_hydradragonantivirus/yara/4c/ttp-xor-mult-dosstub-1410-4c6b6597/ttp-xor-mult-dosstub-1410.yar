rule TTP_XOR_MULT_DOSStub_1410 {
  strings:
    $key_1410 = { 40 78 [2] 34 60 [2] 73 62 [2] 34 73 [2] 7a 7f [2] 76 75 [2] 61 7e [2] 7a 30 [2] 47 }

  condition:
    any of them
}
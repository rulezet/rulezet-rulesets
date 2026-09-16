rule TTP_XOR_MULT_DOSStub_7410 {
  strings:
    $key_7410 = { 20 78 [2] 54 60 [2] 13 62 [2] 54 73 [2] 1a 7f [2] 16 75 [2] 01 7e [2] 1a 30 [2] 27 }

  condition:
    any of them
}
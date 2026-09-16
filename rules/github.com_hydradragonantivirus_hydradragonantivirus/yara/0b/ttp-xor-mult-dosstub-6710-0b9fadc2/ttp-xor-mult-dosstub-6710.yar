rule TTP_XOR_MULT_DOSStub_6710 {
  strings:
    $key_6710 = { 33 78 [2] 47 60 [2] 00 62 [2] 47 73 [2] 09 7f [2] 05 75 [2] 12 7e [2] 09 30 [2] 34 }

  condition:
    any of them
}
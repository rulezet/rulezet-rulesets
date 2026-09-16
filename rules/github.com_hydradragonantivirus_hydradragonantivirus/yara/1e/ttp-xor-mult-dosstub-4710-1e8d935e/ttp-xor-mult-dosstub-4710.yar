rule TTP_XOR_MULT_DOSStub_4710 {
  strings:
    $key_4710 = { 13 78 [2] 67 60 [2] 20 62 [2] 67 73 [2] 29 7f [2] 25 75 [2] 32 7e [2] 29 30 [2] 14 }

  condition:
    any of them
}
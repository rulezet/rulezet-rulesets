rule TTP_XOR_MULT_DOSStub_3510 {
  strings:
    $key_3510 = { 61 78 [2] 15 60 [2] 52 62 [2] 15 73 [2] 5b 7f [2] 57 75 [2] 40 7e [2] 5b 30 [2] 66 }

  condition:
    any of them
}
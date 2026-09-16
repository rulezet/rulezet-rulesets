rule TTP_XOR_MULT_DOSStub_2010 {
  strings:
    $key_2010 = { 74 78 [2] 00 60 [2] 47 62 [2] 00 73 [2] 4e 7f [2] 42 75 [2] 55 7e [2] 4e 30 [2] 73 }

  condition:
    any of them
}
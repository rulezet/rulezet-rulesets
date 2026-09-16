rule TTP_XOR_MULT_DOSStub_2007 {
  strings:
    $key_2007 = { 74 6f [2] 00 77 [2] 47 75 [2] 00 64 [2] 4e 68 [2] 42 62 [2] 55 69 [2] 4e 27 [2] 73 }

  condition:
    any of them
}
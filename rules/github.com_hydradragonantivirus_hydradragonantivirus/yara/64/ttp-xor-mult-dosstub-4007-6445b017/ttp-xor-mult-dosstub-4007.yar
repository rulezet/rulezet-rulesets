rule TTP_XOR_MULT_DOSStub_4007 {
  strings:
    $key_4007 = { 14 6f [2] 60 77 [2] 27 75 [2] 60 64 [2] 2e 68 [2] 22 62 [2] 35 69 [2] 2e 27 [2] 13 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2463 {
  strings:
    $key_2463 = { 70 0b [2] 04 13 [2] 43 11 [2] 04 00 [2] 4a 0c [2] 46 06 [2] 51 0d [2] 4a 43 [2] 77 }

  condition:
    any of them
}
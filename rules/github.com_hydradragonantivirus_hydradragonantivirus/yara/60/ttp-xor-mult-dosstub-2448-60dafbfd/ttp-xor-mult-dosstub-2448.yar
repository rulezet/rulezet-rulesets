rule TTP_XOR_MULT_DOSStub_2448 {
  strings:
    $key_2448 = { 70 20 [2] 04 38 [2] 43 3a [2] 04 2b [2] 4a 27 [2] 46 2d [2] 51 26 [2] 4a 68 [2] 77 }

  condition:
    any of them
}
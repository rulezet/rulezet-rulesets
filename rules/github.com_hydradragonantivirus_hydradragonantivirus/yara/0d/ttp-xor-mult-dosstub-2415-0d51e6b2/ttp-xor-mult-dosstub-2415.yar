rule TTP_XOR_MULT_DOSStub_2415 {
  strings:
    $key_2415 = { 70 7d [2] 04 65 [2] 43 67 [2] 04 76 [2] 4a 7a [2] 46 70 [2] 51 7b [2] 4a 35 [2] 77 }

  condition:
    any of them
}
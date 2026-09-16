rule TTP_XOR_MULT_DOSStub_2465 {
  strings:
    $key_2465 = { 70 0d [2] 04 15 [2] 43 17 [2] 04 06 [2] 4a 0a [2] 46 00 [2] 51 0b [2] 4a 45 [2] 77 }

  condition:
    any of them
}
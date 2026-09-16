rule TTP_XOR_MULT_DOSStub_24f8 {
  strings:
    $key_24f8 = { 70 90 [2] 04 88 [2] 43 8a [2] 04 9b [2] 4a 97 [2] 46 9d [2] 51 96 [2] 4a d8 [2] 77 }

  condition:
    any of them
}
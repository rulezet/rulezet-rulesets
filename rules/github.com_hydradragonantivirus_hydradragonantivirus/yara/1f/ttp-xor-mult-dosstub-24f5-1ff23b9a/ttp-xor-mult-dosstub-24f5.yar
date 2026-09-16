rule TTP_XOR_MULT_DOSStub_24f5 {
  strings:
    $key_24f5 = { 70 9d [2] 04 85 [2] 43 87 [2] 04 96 [2] 4a 9a [2] 46 90 [2] 51 9b [2] 4a d5 [2] 77 }

  condition:
    any of them
}
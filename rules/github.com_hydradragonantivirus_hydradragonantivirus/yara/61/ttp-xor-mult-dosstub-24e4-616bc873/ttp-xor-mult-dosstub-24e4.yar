rule TTP_XOR_MULT_DOSStub_24e4 {
  strings:
    $key_24e4 = { 70 8c [2] 04 94 [2] 43 96 [2] 04 87 [2] 4a 8b [2] 46 81 [2] 51 8a [2] 4a c4 [2] 77 }

  condition:
    any of them
}
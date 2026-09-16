rule TTP_XOR_MULT_DOSStub_2429 {
  strings:
    $key_2429 = { 70 41 [2] 04 59 [2] 43 5b [2] 04 4a [2] 4a 46 [2] 46 4c [2] 51 47 [2] 4a 09 [2] 77 }

  condition:
    any of them
}
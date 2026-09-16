rule TTP_XOR_MULT_DOSStub_2424 {
  strings:
    $key_2424 = { 70 4c [2] 04 54 [2] 43 56 [2] 04 47 [2] 4a 4b [2] 46 41 [2] 51 4a [2] 4a 04 [2] 77 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2408 {
  strings:
    $key_2408 = { 70 60 [2] 04 78 [2] 43 7a [2] 04 6b [2] 4a 67 [2] 46 6d [2] 51 66 [2] 4a 28 [2] 77 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2318 {
  strings:
    $key_2318 = { 77 70 [2] 03 68 [2] 44 6a [2] 03 7b [2] 4d 77 [2] 41 7d [2] 56 76 [2] 4d 38 [2] 70 }

  condition:
    any of them
}
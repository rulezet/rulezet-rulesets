rule TTP_XOR_MULT_DOSStub_2315 {
  strings:
    $key_2315 = { 77 7d [2] 03 65 [2] 44 67 [2] 03 76 [2] 4d 7a [2] 41 70 [2] 56 7b [2] 4d 35 [2] 70 }

  condition:
    any of them
}
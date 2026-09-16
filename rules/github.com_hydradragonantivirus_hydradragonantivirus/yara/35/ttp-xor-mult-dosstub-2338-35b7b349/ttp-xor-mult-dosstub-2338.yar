rule TTP_XOR_MULT_DOSStub_2338 {
  strings:
    $key_2338 = { 77 50 [2] 03 48 [2] 44 4a [2] 03 5b [2] 4d 57 [2] 41 5d [2] 56 56 [2] 4d 18 [2] 70 }

  condition:
    any of them
}
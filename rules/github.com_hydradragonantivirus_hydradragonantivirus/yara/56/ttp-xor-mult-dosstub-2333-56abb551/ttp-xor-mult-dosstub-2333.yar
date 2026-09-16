rule TTP_XOR_MULT_DOSStub_2333 {
  strings:
    $key_2333 = { 77 5b [2] 03 43 [2] 44 41 [2] 03 50 [2] 4d 5c [2] 41 56 [2] 56 5d [2] 4d 13 [2] 70 }

  condition:
    any of them
}
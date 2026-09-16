rule TTP_XOR_MULT_DOSStub_2379 {
  strings:
    $key_2379 = { 77 11 [2] 03 09 [2] 44 0b [2] 03 1a [2] 4d 16 [2] 41 1c [2] 56 17 [2] 4d 59 [2] 70 }

  condition:
    any of them
}
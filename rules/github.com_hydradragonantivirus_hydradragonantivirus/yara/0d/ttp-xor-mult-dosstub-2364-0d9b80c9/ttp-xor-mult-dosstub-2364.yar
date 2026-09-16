rule TTP_XOR_MULT_DOSStub_2364 {
  strings:
    $key_2364 = { 77 0c [2] 03 14 [2] 44 16 [2] 03 07 [2] 4d 0b [2] 41 01 [2] 56 0a [2] 4d 44 [2] 70 }

  condition:
    any of them
}
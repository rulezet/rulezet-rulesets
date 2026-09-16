rule TTP_XOR_MULT_DOSStub_2376 {
  strings:
    $key_2376 = { 77 1e [2] 03 06 [2] 44 04 [2] 03 15 [2] 4d 19 [2] 41 13 [2] 56 18 [2] 4d 56 [2] 70 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2366 {
  strings:
    $key_2366 = { 77 0e [2] 03 16 [2] 44 14 [2] 03 05 [2] 4d 09 [2] 41 03 [2] 56 08 [2] 4d 46 [2] 70 }

  condition:
    any of them
}
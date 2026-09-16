rule TTP_XOR_MULT_DOSStub_3366 {
  strings:
    $key_3366 = { 67 0e [2] 13 16 [2] 54 14 [2] 13 05 [2] 5d 09 [2] 51 03 [2] 46 08 [2] 5d 46 [2] 60 }

  condition:
    any of them
}
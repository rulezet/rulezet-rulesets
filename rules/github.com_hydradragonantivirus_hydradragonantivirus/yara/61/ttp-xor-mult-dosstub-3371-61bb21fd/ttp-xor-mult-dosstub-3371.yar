rule TTP_XOR_MULT_DOSStub_3371 {
  strings:
    $key_3371 = { 67 19 [2] 13 01 [2] 54 03 [2] 13 12 [2] 5d 1e [2] 51 14 [2] 46 1f [2] 5d 51 [2] 60 }

  condition:
    any of them
}
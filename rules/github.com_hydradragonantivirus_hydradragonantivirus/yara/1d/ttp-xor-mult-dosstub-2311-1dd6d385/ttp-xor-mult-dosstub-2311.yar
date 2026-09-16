rule TTP_XOR_MULT_DOSStub_2311 {
  strings:
    $key_2311 = { 77 79 [2] 03 61 [2] 44 63 [2] 03 72 [2] 4d 7e [2] 41 74 [2] 56 7f [2] 4d 31 [2] 70 }

  condition:
    any of them
}
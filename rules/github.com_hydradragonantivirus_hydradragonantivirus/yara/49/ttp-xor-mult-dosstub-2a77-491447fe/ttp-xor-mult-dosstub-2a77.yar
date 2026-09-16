rule TTP_XOR_MULT_DOSStub_2a77 {
  strings:
    $key_2a77 = { 7e 1f [2] 0a 07 [2] 4d 05 [2] 0a 14 [2] 44 18 [2] 48 12 [2] 5f 19 [2] 44 57 [2] 79 }

  condition:
    any of them
}
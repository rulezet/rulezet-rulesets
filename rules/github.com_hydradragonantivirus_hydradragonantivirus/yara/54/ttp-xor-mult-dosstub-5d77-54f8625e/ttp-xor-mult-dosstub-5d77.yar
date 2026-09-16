rule TTP_XOR_MULT_DOSStub_5d77 {
  strings:
    $key_5d77 = { 09 1f [2] 7d 07 [2] 3a 05 [2] 7d 14 [2] 33 18 [2] 3f 12 [2] 28 19 [2] 33 57 [2] 0e }

  condition:
    any of them
}
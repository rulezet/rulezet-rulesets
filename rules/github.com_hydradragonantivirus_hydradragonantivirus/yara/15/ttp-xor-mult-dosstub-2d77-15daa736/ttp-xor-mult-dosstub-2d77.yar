rule TTP_XOR_MULT_DOSStub_2d77 {
  strings:
    $key_2d77 = { 79 1f [2] 0d 07 [2] 4a 05 [2] 0d 14 [2] 43 18 [2] 4f 12 [2] 58 19 [2] 43 57 [2] 7e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2327 {
  strings:
    $key_2327 = { 77 4f [2] 03 57 [2] 44 55 [2] 03 44 [2] 4d 48 [2] 41 42 [2] 56 49 [2] 4d 07 [2] 70 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7627 {
  strings:
    $key_7627 = { 22 4f [2] 56 57 [2] 11 55 [2] 56 44 [2] 18 48 [2] 14 42 [2] 03 49 [2] 18 07 [2] 25 }

  condition:
    any of them
}
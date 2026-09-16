rule TTP_XOR_MULT_DOSStub_6727 {
  strings:
    $key_6727 = { 33 4f [2] 47 57 [2] 00 55 [2] 47 44 [2] 09 48 [2] 05 42 [2] 12 49 [2] 09 07 [2] 34 }

  condition:
    any of them
}
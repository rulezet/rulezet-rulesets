rule TTP_XOR_MULT_DOSStub_5127 {
  strings:
    $key_5127 = { 05 4f [2] 71 57 [2] 36 55 [2] 71 44 [2] 3f 48 [2] 33 42 [2] 24 49 [2] 3f 07 [2] 02 }

  condition:
    any of them
}
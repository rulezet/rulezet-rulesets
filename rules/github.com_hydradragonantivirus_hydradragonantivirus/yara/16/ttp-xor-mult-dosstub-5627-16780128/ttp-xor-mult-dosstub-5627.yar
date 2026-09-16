rule TTP_XOR_MULT_DOSStub_5627 {
  strings:
    $key_5627 = { 02 4f [2] 76 57 [2] 31 55 [2] 76 44 [2] 38 48 [2] 34 42 [2] 23 49 [2] 38 07 [2] 05 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3321 {
  strings:
    $key_3321 = { 67 49 [2] 13 51 [2] 54 53 [2] 13 42 [2] 5d 4e [2] 51 44 [2] 46 4f [2] 5d 01 [2] 60 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4726 {
  strings:
    $key_4726 = { 13 4e [2] 67 56 [2] 20 54 [2] 67 45 [2] 29 49 [2] 25 43 [2] 32 48 [2] 29 06 [2] 14 }

  condition:
    any of them
}
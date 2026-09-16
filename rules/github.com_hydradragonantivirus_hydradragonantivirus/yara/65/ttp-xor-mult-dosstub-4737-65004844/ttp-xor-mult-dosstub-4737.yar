rule TTP_XOR_MULT_DOSStub_4737 {
  strings:
    $key_4737 = { 13 5f [2] 67 47 [2] 20 45 [2] 67 54 [2] 29 58 [2] 25 52 [2] 32 59 [2] 29 17 [2] 14 }

  condition:
    any of them
}
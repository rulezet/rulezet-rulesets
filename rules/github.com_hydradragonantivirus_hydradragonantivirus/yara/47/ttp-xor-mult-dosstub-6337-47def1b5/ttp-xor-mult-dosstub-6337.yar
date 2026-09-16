rule TTP_XOR_MULT_DOSStub_6337 {
  strings:
    $key_6337 = { 37 5f [2] 43 47 [2] 04 45 [2] 43 54 [2] 0d 58 [2] 01 52 [2] 16 59 [2] 0d 17 [2] 30 }

  condition:
    any of them
}
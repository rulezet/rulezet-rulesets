rule TTP_XOR_MULT_DOSStub_5047 {
  strings:
    $key_5047 = { 04 2f [2] 70 37 [2] 37 35 [2] 70 24 [2] 3e 28 [2] 32 22 [2] 25 29 [2] 3e 67 [2] 03 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4337 {
  strings:
    $key_4337 = { 17 5f [2] 63 47 [2] 24 45 [2] 63 54 [2] 2d 58 [2] 21 52 [2] 36 59 [2] 2d 17 [2] 10 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5337 {
  strings:
    $key_5337 = { 07 5f [2] 73 47 [2] 34 45 [2] 73 54 [2] 3d 58 [2] 31 52 [2] 26 59 [2] 3d 17 [2] 00 }

  condition:
    any of them
}
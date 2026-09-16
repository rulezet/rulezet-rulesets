rule TTP_XOR_MULT_DOSStub_5330 {
  strings:
    $key_5330 = { 07 58 [2] 73 40 [2] 34 42 [2] 73 53 [2] 3d 5f [2] 31 55 [2] 26 5e [2] 3d 10 [2] 00 }

  condition:
    any of them
}
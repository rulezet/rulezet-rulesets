rule TTP_XOR_MULT_DOSStub_4310 {
  strings:
    $key_4310 = { 17 78 [2] 63 60 [2] 24 62 [2] 63 73 [2] 2d 7f [2] 21 75 [2] 36 7e [2] 2d 30 [2] 10 }

  condition:
    any of them
}
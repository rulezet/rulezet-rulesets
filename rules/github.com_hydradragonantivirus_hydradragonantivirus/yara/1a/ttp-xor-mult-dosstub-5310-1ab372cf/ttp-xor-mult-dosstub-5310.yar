rule TTP_XOR_MULT_DOSStub_5310 {
  strings:
    $key_5310 = { 07 78 [2] 73 60 [2] 34 62 [2] 73 73 [2] 3d 7f [2] 31 75 [2] 26 7e [2] 3d 30 [2] 00 }

  condition:
    any of them
}
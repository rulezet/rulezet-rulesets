rule TTP_XOR_MULT_DOSStub_5331 {
  strings:
    $key_5331 = { 07 59 [2] 73 41 [2] 34 43 [2] 73 52 [2] 3d 5e [2] 31 54 [2] 26 5f [2] 3d 11 [2] 00 }

  condition:
    any of them
}
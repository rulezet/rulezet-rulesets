rule TTP_XOR_MULT_DOSStub_53b3 {
  strings:
    $key_53b3 = { 07 db [2] 73 c3 [2] 34 c1 [2] 73 d0 [2] 3d dc [2] 31 d6 [2] 26 dd [2] 3d 93 [2] 00 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_53a9 {
  strings:
    $key_53a9 = { 07 c1 [2] 73 d9 [2] 34 db [2] 73 ca [2] 3d c6 [2] 31 cc [2] 26 c7 [2] 3d 89 [2] 00 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_62a9 {
  strings:
    $key_62a9 = { 36 c1 [2] 42 d9 [2] 05 db [2] 42 ca [2] 0c c6 [2] 00 cc [2] 17 c7 [2] 0c 89 [2] 31 }

  condition:
    any of them
}
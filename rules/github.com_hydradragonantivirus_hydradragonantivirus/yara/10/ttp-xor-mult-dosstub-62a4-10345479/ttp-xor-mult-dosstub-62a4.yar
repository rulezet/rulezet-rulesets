rule TTP_XOR_MULT_DOSStub_62a4 {
  strings:
    $key_62a4 = { 36 cc [2] 42 d4 [2] 05 d6 [2] 42 c7 [2] 0c cb [2] 00 c1 [2] 17 ca [2] 0c 84 [2] 31 }

  condition:
    any of them
}
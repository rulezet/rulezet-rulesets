rule TTP_XOR_MULT_DOSStub_67a4 {
  strings:
    $key_67a4 = { 33 cc [2] 47 d4 [2] 00 d6 [2] 47 c7 [2] 09 cb [2] 05 c1 [2] 12 ca [2] 09 84 [2] 34 }

  condition:
    any of them
}
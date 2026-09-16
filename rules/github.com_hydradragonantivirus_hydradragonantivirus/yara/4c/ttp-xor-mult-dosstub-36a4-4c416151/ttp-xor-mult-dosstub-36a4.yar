rule TTP_XOR_MULT_DOSStub_36a4 {
  strings:
    $key_36a4 = { 62 cc [2] 16 d4 [2] 51 d6 [2] 16 c7 [2] 58 cb [2] 54 c1 [2] 43 ca [2] 58 84 [2] 65 }

  condition:
    any of them
}
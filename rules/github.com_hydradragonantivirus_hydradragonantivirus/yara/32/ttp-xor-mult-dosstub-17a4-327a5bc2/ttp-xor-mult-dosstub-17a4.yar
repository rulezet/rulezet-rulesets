rule TTP_XOR_MULT_DOSStub_17a4 {
  strings:
    $key_17a4 = { 43 cc [2] 37 d4 [2] 70 d6 [2] 37 c7 [2] 79 cb [2] 75 c1 [2] 62 ca [2] 79 84 [2] 44 }

  condition:
    any of them
}
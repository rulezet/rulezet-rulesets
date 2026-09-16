rule TTP_XOR_MULT_DOSStub_12a4 {
  strings:
    $key_12a4 = { 46 cc [2] 32 d4 [2] 75 d6 [2] 32 c7 [2] 7c cb [2] 70 c1 [2] 67 ca [2] 7c 84 [2] 41 }

  condition:
    any of them
}
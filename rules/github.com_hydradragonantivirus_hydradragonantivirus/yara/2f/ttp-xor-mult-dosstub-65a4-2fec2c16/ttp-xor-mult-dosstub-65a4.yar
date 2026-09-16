rule TTP_XOR_MULT_DOSStub_65a4 {
  strings:
    $key_65a4 = { 31 cc [2] 45 d4 [2] 02 d6 [2] 45 c7 [2] 0b cb [2] 07 c1 [2] 10 ca [2] 0b 84 [2] 36 }

  condition:
    any of them
}
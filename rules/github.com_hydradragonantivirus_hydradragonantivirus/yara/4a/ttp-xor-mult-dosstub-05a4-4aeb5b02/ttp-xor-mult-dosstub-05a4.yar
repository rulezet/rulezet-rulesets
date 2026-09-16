rule TTP_XOR_MULT_DOSStub_05a4 {
  strings:
    $key_05a4 = { 51 cc [2] 25 d4 [2] 62 d6 [2] 25 c7 [2] 6b cb [2] 67 c1 [2] 70 ca [2] 6b 84 [2] 56 }

  condition:
    any of them
}
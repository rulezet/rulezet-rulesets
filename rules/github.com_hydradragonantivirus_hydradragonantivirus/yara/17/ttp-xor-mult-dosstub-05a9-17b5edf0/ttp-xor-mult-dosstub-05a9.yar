rule TTP_XOR_MULT_DOSStub_05a9 {
  strings:
    $key_05a9 = { 51 c1 [2] 25 d9 [2] 62 db [2] 25 ca [2] 6b c6 [2] 67 cc [2] 70 c7 [2] 6b 89 [2] 56 }

  condition:
    any of them
}
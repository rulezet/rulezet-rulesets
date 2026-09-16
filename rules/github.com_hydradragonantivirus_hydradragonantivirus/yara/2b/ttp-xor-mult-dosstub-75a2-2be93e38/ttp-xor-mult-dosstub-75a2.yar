rule TTP_XOR_MULT_DOSStub_75a2 {
  strings:
    $key_75a2 = { 21 ca [2] 55 d2 [2] 12 d0 [2] 55 c1 [2] 1b cd [2] 17 c7 [2] 00 cc [2] 1b 82 [2] 26 }

  condition:
    any of them
}
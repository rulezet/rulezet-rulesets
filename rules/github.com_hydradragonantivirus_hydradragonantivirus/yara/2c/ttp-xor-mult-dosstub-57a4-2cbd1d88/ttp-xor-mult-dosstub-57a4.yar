rule TTP_XOR_MULT_DOSStub_57a4 {
  strings:
    $key_57a4 = { 03 cc [2] 77 d4 [2] 30 d6 [2] 77 c7 [2] 39 cb [2] 35 c1 [2] 22 ca [2] 39 84 [2] 04 }

  condition:
    any of them
}
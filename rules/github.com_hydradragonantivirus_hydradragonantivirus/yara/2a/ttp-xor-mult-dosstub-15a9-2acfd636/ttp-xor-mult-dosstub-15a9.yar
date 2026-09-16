rule TTP_XOR_MULT_DOSStub_15a9 {
  strings:
    $key_15a9 = { 41 c1 [2] 35 d9 [2] 72 db [2] 35 ca [2] 7b c6 [2] 77 cc [2] 60 c7 [2] 7b 89 [2] 46 }

  condition:
    any of them
}
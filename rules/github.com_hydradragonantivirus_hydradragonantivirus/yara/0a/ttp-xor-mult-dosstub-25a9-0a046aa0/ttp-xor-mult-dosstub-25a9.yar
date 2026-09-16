rule TTP_XOR_MULT_DOSStub_25a9 {
  strings:
    $key_25a9 = { 71 c1 [2] 05 d9 [2] 42 db [2] 05 ca [2] 4b c6 [2] 47 cc [2] 50 c7 [2] 4b 89 [2] 76 }

  condition:
    any of them
}
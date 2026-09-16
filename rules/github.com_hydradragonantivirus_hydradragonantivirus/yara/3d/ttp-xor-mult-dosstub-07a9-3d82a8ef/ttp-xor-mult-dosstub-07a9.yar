rule TTP_XOR_MULT_DOSStub_07a9 {
  strings:
    $key_07a9 = { 53 c1 [2] 27 d9 [2] 60 db [2] 27 ca [2] 69 c6 [2] 65 cc [2] 72 c7 [2] 69 89 [2] 54 }

  condition:
    any of them
}
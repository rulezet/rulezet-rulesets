rule TTP_XOR_MULT_DOSStub_17a9 {
  strings:
    $key_17a9 = { 43 c1 [2] 37 d9 [2] 70 db [2] 37 ca [2] 79 c6 [2] 75 cc [2] 62 c7 [2] 79 89 [2] 44 }

  condition:
    any of them
}
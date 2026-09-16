rule TTP_XOR_MULT_DOSStub_26a9 {
  strings:
    $key_26a9 = { 72 c1 [2] 06 d9 [2] 41 db [2] 06 ca [2] 48 c6 [2] 44 cc [2] 53 c7 [2] 48 89 [2] 75 }

  condition:
    any of them
}
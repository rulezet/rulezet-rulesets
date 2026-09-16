rule TTP_XOR_MULT_DOSStub_32a9 {
  strings:
    $key_32a9 = { 66 c1 [2] 12 d9 [2] 55 db [2] 12 ca [2] 5c c6 [2] 50 cc [2] 47 c7 [2] 5c 89 [2] 61 }

  condition:
    any of them
}
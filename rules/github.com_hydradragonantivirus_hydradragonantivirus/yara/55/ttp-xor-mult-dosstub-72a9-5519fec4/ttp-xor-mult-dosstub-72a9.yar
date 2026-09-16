rule TTP_XOR_MULT_DOSStub_72a9 {
  strings:
    $key_72a9 = { 26 c1 [2] 52 d9 [2] 15 db [2] 52 ca [2] 1c c6 [2] 10 cc [2] 07 c7 [2] 1c 89 [2] 21 }

  condition:
    any of them
}
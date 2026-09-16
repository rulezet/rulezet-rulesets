rule TTP_XOR_MULT_DOSStub_f2a9 {
  strings:
    $key_f2a9 = { a6 c1 [2] d2 d9 [2] 95 db [2] d2 ca [2] 9c c6 [2] 90 cc [2] 87 c7 [2] 9c 89 [2] a1 }

  condition:
    any of them
}
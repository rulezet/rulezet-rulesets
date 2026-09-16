rule TTP_XOR_MULT_DOSStub_f2a2 {
  strings:
    $key_f2a2 = { a6 ca [2] d2 d2 [2] 95 d0 [2] d2 c1 [2] 9c cd [2] 90 c7 [2] 87 cc [2] 9c 82 [2] a1 }

  condition:
    any of them
}
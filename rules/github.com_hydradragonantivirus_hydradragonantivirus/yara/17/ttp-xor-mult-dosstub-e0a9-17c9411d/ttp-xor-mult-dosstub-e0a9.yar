rule TTP_XOR_MULT_DOSStub_e0a9 {
  strings:
    $key_e0a9 = { b4 c1 [2] c0 d9 [2] 87 db [2] c0 ca [2] 8e c6 [2] 82 cc [2] 95 c7 [2] 8e 89 [2] b3 }

  condition:
    any of them
}
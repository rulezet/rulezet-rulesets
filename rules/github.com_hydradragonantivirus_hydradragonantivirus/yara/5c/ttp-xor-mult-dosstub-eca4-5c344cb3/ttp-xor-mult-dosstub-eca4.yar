rule TTP_XOR_MULT_DOSStub_eca4 {
  strings:
    $key_eca4 = { b8 cc [2] cc d4 [2] 8b d6 [2] cc c7 [2] 82 cb [2] 8e c1 [2] 99 ca [2] 82 84 [2] bf }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_45a2 {
  strings:
    $key_45a2 = { 11 ca [2] 65 d2 [2] 22 d0 [2] 65 c1 [2] 2b cd [2] 27 c7 [2] 30 cc [2] 2b 82 [2] 16 }

  condition:
    any of them
}
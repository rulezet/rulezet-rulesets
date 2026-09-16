rule TTP_XOR_MULT_DOSStub_74a2 {
  strings:
    $key_74a2 = { 20 ca [2] 54 d2 [2] 13 d0 [2] 54 c1 [2] 1a cd [2] 16 c7 [2] 01 cc [2] 1a 82 [2] 27 }

  condition:
    any of them
}
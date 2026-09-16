rule TTP_XOR_MULT_DOSStub_6ca2 {
  strings:
    $key_6ca2 = { 38 ca [2] 4c d2 [2] 0b d0 [2] 4c c1 [2] 02 cd [2] 0e c7 [2] 19 cc [2] 02 82 [2] 3f }

  condition:
    any of them
}
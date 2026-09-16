rule TTP_XOR_MULT_DOSStub_3ca2 {
  strings:
    $key_3ca2 = { 68 ca [2] 1c d2 [2] 5b d0 [2] 1c c1 [2] 52 cd [2] 5e c7 [2] 49 cc [2] 52 82 [2] 6f }

  condition:
    any of them
}
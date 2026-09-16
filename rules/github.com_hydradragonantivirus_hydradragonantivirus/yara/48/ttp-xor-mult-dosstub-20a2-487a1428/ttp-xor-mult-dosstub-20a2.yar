rule TTP_XOR_MULT_DOSStub_20a2 {
  strings:
    $key_20a2 = { 74 ca [2] 00 d2 [2] 47 d0 [2] 00 c1 [2] 4e cd [2] 42 c7 [2] 55 cc [2] 4e 82 [2] 73 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_10a2 {
  strings:
    $key_10a2 = { 44 ca [2] 30 d2 [2] 77 d0 [2] 30 c1 [2] 7e cd [2] 72 c7 [2] 65 cc [2] 7e 82 [2] 43 }

  condition:
    any of them
}
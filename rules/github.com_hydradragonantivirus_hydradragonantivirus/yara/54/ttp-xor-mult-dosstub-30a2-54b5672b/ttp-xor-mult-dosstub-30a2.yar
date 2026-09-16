rule TTP_XOR_MULT_DOSStub_30a2 {
  strings:
    $key_30a2 = { 64 ca [2] 10 d2 [2] 57 d0 [2] 10 c1 [2] 5e cd [2] 52 c7 [2] 45 cc [2] 5e 82 [2] 63 }

  condition:
    any of them
}
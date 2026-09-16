rule TTP_XOR_MULT_DOSStub_44a2 {
  strings:
    $key_44a2 = { 10 ca [2] 64 d2 [2] 23 d0 [2] 64 c1 [2] 2a cd [2] 26 c7 [2] 31 cc [2] 2a 82 [2] 17 }

  condition:
    any of them
}
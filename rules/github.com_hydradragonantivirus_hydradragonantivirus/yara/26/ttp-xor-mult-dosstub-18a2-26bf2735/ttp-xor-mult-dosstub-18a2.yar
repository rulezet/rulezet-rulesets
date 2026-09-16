rule TTP_XOR_MULT_DOSStub_18a2 {
  strings:
    $key_18a2 = { 4c ca [2] 38 d2 [2] 7f d0 [2] 38 c1 [2] 76 cd [2] 7a c7 [2] 6d cc [2] 76 82 [2] 4b }

  condition:
    any of them
}
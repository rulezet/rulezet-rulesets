rule TTP_XOR_MULT_DOSStub_0aa2 {
  strings:
    $key_0aa2 = { 5e ca [2] 2a d2 [2] 6d d0 [2] 2a c1 [2] 64 cd [2] 68 c7 [2] 7f cc [2] 64 82 [2] 59 }

  condition:
    any of them
}
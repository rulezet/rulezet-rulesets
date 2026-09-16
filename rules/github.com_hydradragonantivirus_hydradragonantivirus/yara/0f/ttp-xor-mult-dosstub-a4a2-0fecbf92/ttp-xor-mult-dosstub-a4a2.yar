rule TTP_XOR_MULT_DOSStub_a4a2 {
  strings:
    $key_a4a2 = { f0 ca [2] 84 d2 [2] c3 d0 [2] 84 c1 [2] ca cd [2] c6 c7 [2] d1 cc [2] ca 82 [2] f7 }

  condition:
    any of them
}
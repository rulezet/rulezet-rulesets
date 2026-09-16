rule TTP_XOR_MULT_DOSStub_a2a2 {
  strings:
    $key_a2a2 = { f6 ca [2] 82 d2 [2] c5 d0 [2] 82 c1 [2] cc cd [2] c0 c7 [2] d7 cc [2] cc 82 [2] f1 }

  condition:
    any of them
}
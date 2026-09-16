rule TTP_XOR_MULT_DOSStub_a0a2 {
  strings:
    $key_a0a2 = { f4 ca [2] 80 d2 [2] c7 d0 [2] 80 c1 [2] ce cd [2] c2 c7 [2] d5 cc [2] ce 82 [2] f3 }

  condition:
    any of them
}
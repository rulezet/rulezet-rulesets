rule TTP_XOR_MULT_DOSStub_83a2 {
  strings:
    $key_83a2 = { d7 ca [2] a3 d2 [2] e4 d0 [2] a3 c1 [2] ed cd [2] e1 c7 [2] f6 cc [2] ed 82 [2] d0 }

  condition:
    any of them
}
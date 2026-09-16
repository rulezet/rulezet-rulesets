rule TTP_XOR_MULT_DOSStub_83aa {
  strings:
    $key_83aa = { d7 c2 [2] a3 da [2] e4 d8 [2] a3 c9 [2] ed c5 [2] e1 cf [2] f6 c4 [2] ed 8a [2] d0 }

  condition:
    any of them
}
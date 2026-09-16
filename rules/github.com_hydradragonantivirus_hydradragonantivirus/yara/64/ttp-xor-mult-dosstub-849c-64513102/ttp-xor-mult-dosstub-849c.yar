rule TTP_XOR_MULT_DOSStub_849c {
  strings:
    $key_849c = { d0 f4 [2] a4 ec [2] e3 ee [2] a4 ff [2] ea f3 [2] e6 f9 [2] f1 f2 [2] ea bc [2] d7 }

  condition:
    any of them
}
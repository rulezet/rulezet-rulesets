rule TTP_XOR_MULT_DOSStub_a79c {
  strings:
    $key_a79c = { f3 f4 [2] 87 ec [2] c0 ee [2] 87 ff [2] c9 f3 [2] c5 f9 [2] d2 f2 [2] c9 bc [2] f4 }

  condition:
    any of them
}
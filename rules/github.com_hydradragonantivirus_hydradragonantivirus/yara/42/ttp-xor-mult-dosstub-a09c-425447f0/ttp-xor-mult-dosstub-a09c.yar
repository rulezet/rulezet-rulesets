rule TTP_XOR_MULT_DOSStub_a09c {
  strings:
    $key_a09c = { f4 f4 [2] 80 ec [2] c7 ee [2] 80 ff [2] ce f3 [2] c2 f9 [2] d5 f2 [2] ce bc [2] f3 }

  condition:
    any of them
}
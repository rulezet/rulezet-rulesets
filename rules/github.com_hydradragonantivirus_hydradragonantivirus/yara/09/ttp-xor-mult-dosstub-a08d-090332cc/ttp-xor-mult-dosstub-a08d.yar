rule TTP_XOR_MULT_DOSStub_a08d {
  strings:
    $key_a08d = { f4 e5 [2] 80 fd [2] c7 ff [2] 80 ee [2] ce e2 [2] c2 e8 [2] d5 e3 [2] ce ad [2] f3 }

  condition:
    any of them
}
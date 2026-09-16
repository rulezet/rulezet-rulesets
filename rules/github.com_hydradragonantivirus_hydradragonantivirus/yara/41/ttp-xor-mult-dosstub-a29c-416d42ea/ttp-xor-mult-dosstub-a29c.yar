rule TTP_XOR_MULT_DOSStub_a29c {
  strings:
    $key_a29c = { f6 f4 [2] 82 ec [2] c5 ee [2] 82 ff [2] cc f3 [2] c0 f9 [2] d7 f2 [2] cc bc [2] f1 }

  condition:
    any of them
}
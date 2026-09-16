rule TTP_XOR_MULT_DOSStub_829c {
  strings:
    $key_829c = { d6 f4 [2] a2 ec [2] e5 ee [2] a2 ff [2] ec f3 [2] e0 f9 [2] f7 f2 [2] ec bc [2] d1 }

  condition:
    any of them
}
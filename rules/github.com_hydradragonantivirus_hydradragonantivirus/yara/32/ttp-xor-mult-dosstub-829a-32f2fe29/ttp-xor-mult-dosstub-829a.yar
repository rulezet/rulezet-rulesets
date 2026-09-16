rule TTP_XOR_MULT_DOSStub_829a {
  strings:
    $key_829a = { d6 f2 [2] a2 ea [2] e5 e8 [2] a2 f9 [2] ec f5 [2] e0 ff [2] f7 f4 [2] ec ba [2] d1 }

  condition:
    any of them
}
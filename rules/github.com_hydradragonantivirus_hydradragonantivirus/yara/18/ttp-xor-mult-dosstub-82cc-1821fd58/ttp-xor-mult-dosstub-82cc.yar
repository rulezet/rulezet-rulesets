rule TTP_XOR_MULT_DOSStub_82cc {
  strings:
    $key_82cc = { d6 a4 [2] a2 bc [2] e5 be [2] a2 af [2] ec a3 [2] e0 a9 [2] f7 a2 [2] ec ec [2] d1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_a9cc {
  strings:
    $key_a9cc = { fd a4 [2] 89 bc [2] ce be [2] 89 af [2] c7 a3 [2] cb a9 [2] dc a2 [2] c7 ec [2] fa }

  condition:
    any of them
}
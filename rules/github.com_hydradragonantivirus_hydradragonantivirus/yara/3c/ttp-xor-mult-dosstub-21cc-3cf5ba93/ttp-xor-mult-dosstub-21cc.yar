rule TTP_XOR_MULT_DOSStub_21cc {
  strings:
    $key_21cc = { 75 a4 [2] 01 bc [2] 46 be [2] 01 af [2] 4f a3 [2] 43 a9 [2] 54 a2 [2] 4f ec [2] 72 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_41cc {
  strings:
    $key_41cc = { 15 a4 [2] 61 bc [2] 26 be [2] 61 af [2] 2f a3 [2] 23 a9 [2] 34 a2 [2] 2f ec [2] 12 }

  condition:
    any of them
}
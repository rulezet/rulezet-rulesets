rule TTP_XOR_MULT_DOSStub_51cc {
  strings:
    $key_51cc = { 05 a4 [2] 71 bc [2] 36 be [2] 71 af [2] 3f a3 [2] 33 a9 [2] 24 a2 [2] 3f ec [2] 02 }

  condition:
    any of them
}
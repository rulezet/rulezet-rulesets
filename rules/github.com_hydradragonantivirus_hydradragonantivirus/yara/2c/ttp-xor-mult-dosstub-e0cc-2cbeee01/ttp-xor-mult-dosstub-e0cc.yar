rule TTP_XOR_MULT_DOSStub_e0cc {
  strings:
    $key_e0cc = { b4 a4 [2] c0 bc [2] 87 be [2] c0 af [2] 8e a3 [2] 82 a9 [2] 95 a2 [2] 8e ec [2] b3 }

  condition:
    any of them
}
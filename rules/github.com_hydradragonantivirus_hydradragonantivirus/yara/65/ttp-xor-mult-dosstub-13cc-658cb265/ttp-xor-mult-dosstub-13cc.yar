rule TTP_XOR_MULT_DOSStub_13cc {
  strings:
    $key_13cc = { 47 a4 [2] 33 bc [2] 74 be [2] 33 af [2] 7d a3 [2] 71 a9 [2] 66 a2 [2] 7d ec [2] 40 }

  condition:
    any of them
}
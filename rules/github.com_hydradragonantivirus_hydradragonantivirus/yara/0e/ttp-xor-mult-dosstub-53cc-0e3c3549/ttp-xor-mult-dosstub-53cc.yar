rule TTP_XOR_MULT_DOSStub_53cc {
  strings:
    $key_53cc = { 07 a4 [2] 73 bc [2] 34 be [2] 73 af [2] 3d a3 [2] 31 a9 [2] 26 a2 [2] 3d ec [2] 00 }

  condition:
    any of them
}
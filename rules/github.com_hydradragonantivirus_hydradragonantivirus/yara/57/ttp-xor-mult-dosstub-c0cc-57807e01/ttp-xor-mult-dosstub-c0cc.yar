rule TTP_XOR_MULT_DOSStub_c0cc {
  strings:
    $key_c0cc = { 94 a4 [2] e0 bc [2] a7 be [2] e0 af [2] ae a3 [2] a2 a9 [2] b5 a2 [2] ae ec [2] 93 }

  condition:
    any of them
}
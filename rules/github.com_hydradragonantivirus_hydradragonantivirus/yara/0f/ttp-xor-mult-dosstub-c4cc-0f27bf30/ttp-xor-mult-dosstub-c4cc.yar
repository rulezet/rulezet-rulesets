rule TTP_XOR_MULT_DOSStub_c4cc {
  strings:
    $key_c4cc = { 90 a4 [2] e4 bc [2] a3 be [2] e4 af [2] aa a3 [2] a6 a9 [2] b1 a2 [2] aa ec [2] 97 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_eb8f {
  strings:
    $key_eb8f = { bf e7 [2] cb ff [2] 8c fd [2] cb ec [2] 85 e0 [2] 89 ea [2] 9e e1 [2] 85 af [2] b8 }

  condition:
    any of them
}
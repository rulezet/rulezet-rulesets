rule TTP_XOR_MULT_DOSStub_eb8d {
  strings:
    $key_eb8d = { bf e5 [2] cb fd [2] 8c ff [2] cb ee [2] 85 e2 [2] 89 e8 [2] 9e e3 [2] 85 ad [2] b8 }

  condition:
    any of them
}
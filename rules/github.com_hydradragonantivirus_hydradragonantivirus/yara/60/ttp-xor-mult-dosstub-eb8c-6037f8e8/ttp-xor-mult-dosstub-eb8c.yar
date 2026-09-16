rule TTP_XOR_MULT_DOSStub_eb8c {
  strings:
    $key_eb8c = { bf e4 [2] cb fc [2] 8c fe [2] cb ef [2] 85 e3 [2] 89 e9 [2] 9e e2 [2] 85 ac [2] b8 }

  condition:
    any of them
}
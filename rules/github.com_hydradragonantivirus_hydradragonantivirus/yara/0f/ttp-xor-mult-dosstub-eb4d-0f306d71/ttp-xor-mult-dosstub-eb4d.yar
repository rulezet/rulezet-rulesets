rule TTP_XOR_MULT_DOSStub_eb4d {
  strings:
    $key_eb4d = { bf 25 [2] cb 3d [2] 8c 3f [2] cb 2e [2] 85 22 [2] 89 28 [2] 9e 23 [2] 85 6d [2] b8 }

  condition:
    any of them
}
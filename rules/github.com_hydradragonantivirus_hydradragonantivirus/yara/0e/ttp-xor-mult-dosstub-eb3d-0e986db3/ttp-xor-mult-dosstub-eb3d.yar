rule TTP_XOR_MULT_DOSStub_eb3d {
  strings:
    $key_eb3d = { bf 55 [2] cb 4d [2] 8c 4f [2] cb 5e [2] 85 52 [2] 89 58 [2] 9e 53 [2] 85 1d [2] b8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_eb10 {
  strings:
    $key_eb10 = { bf 78 [2] cb 60 [2] 8c 62 [2] cb 73 [2] 85 7f [2] 89 75 [2] 9e 7e [2] 85 30 [2] b8 }

  condition:
    any of them
}
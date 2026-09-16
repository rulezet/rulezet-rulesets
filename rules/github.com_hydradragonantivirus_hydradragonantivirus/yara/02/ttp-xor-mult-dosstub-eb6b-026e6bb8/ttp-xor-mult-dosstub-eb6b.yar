rule TTP_XOR_MULT_DOSStub_eb6b {
  strings:
    $key_eb6b = { bf 03 [2] cb 1b [2] 8c 19 [2] cb 08 [2] 85 04 [2] 89 0e [2] 9e 05 [2] 85 4b [2] b8 }

  condition:
    any of them
}
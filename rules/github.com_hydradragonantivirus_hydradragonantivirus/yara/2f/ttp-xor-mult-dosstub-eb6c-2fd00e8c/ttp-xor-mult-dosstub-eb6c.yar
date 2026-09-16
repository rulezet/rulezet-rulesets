rule TTP_XOR_MULT_DOSStub_eb6c {
  strings:
    $key_eb6c = { bf 04 [2] cb 1c [2] 8c 1e [2] cb 0f [2] 85 03 [2] 89 09 [2] 9e 02 [2] 85 4c [2] b8 }

  condition:
    any of them
}
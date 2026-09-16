rule TTP_XOR_MULT_DOSStub_bef3 {
  strings:
    $key_bef3 = { ea 9b [2] 9e 83 [2] d9 81 [2] 9e 90 [2] d0 9c [2] dc 96 [2] cb 9d [2] d0 d3 [2] ed }

  condition:
    any of them
}
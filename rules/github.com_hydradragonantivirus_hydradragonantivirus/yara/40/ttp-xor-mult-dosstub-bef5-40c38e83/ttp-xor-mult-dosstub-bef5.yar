rule TTP_XOR_MULT_DOSStub_bef5 {
  strings:
    $key_bef5 = { ea 9d [2] 9e 85 [2] d9 87 [2] 9e 96 [2] d0 9a [2] dc 90 [2] cb 9b [2] d0 d5 [2] ed }

  condition:
    any of them
}
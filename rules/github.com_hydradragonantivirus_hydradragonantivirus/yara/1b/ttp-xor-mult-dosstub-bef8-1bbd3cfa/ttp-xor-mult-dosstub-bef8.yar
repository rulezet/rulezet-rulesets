rule TTP_XOR_MULT_DOSStub_bef8 {
  strings:
    $key_bef8 = { ea 90 [2] 9e 88 [2] d9 8a [2] 9e 9b [2] d0 97 [2] dc 9d [2] cb 96 [2] d0 d8 [2] ed }

  condition:
    any of them
}
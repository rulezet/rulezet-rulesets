rule TTP_XOR_MULT_DOSStub_bee9 {
  strings:
    $key_bee9 = { ea 81 [2] 9e 99 [2] d9 9b [2] 9e 8a [2] d0 86 [2] dc 8c [2] cb 87 [2] d0 c9 [2] ed }

  condition:
    any of them
}
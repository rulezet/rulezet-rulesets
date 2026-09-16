rule TTP_XOR_MULT_DOSStub_be32 {
  strings:
    $key_be32 = { ea 5a [2] 9e 42 [2] d9 40 [2] 9e 51 [2] d0 5d [2] dc 57 [2] cb 5c [2] d0 12 [2] ed }

  condition:
    any of them
}
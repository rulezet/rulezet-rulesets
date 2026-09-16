rule TTP_XOR_MULT_DOSStub_be52 {
  strings:
    $key_be52 = { ea 3a [2] 9e 22 [2] d9 20 [2] 9e 31 [2] d0 3d [2] dc 37 [2] cb 3c [2] d0 72 [2] ed }

  condition:
    any of them
}
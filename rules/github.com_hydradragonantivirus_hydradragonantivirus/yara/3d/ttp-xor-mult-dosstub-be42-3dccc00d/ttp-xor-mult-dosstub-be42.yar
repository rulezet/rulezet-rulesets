rule TTP_XOR_MULT_DOSStub_be42 {
  strings:
    $key_be42 = { ea 2a [2] 9e 32 [2] d9 30 [2] 9e 21 [2] d0 2d [2] dc 27 [2] cb 2c [2] d0 62 [2] ed }

  condition:
    any of them
}
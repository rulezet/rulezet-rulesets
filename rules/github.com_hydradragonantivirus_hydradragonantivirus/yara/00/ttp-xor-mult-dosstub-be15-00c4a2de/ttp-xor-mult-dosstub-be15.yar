rule TTP_XOR_MULT_DOSStub_be15 {
  strings:
    $key_be15 = { ea 7d [2] 9e 65 [2] d9 67 [2] 9e 76 [2] d0 7a [2] dc 70 [2] cb 7b [2] d0 35 [2] ed }

  condition:
    any of them
}